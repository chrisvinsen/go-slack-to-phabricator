// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// [START functions_slack_search]

// Package slack is a Cloud Function which recieves a query from
// a Slack command and responds with the KG API result.
package slack

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/uber/gonduit"
	"github.com/uber/gonduit/core"
	"github.com/uber/gonduit/requests"
	"github.com/slack-go/slack"
)

const (
	version                     = "v0"
	slackRequestTimestampHeader = "X-Slack-Request-Timestamp"
	slackSignatureHeader        = "X-Slack-Signature"
	maxCharacterLabel           = 72
	limitQuery                  = 100
)

type oldTimeStampError struct {
	s string
}

func (e *oldTimeStampError) Error() string {
	return e.s
}

// F uses the Knowledge Graph API to search for a query provided by a Slack command.
// [/]
func SlashCommand(w http.ResponseWriter, r *http.Request) {
	var env Environment
	w, r, env = setupHttpRequest(w, r)

	if len(r.Form["text"]) == 0 || len(r.Form["trigger_id"]) == 0 {
		log.Fatalln("empty text in form")
	}
	res, err := makeSearchRequest(env, r.Form["text"][0], r.Form["trigger_id"][0])
	if err != nil {
		fmt.Printf("makeSearchRequest: %v", err)
	}
	if res != nil {
		if err = json.NewEncoder(w).Encode(res); err != nil {
			log.Fatalf("json.Marshal: %v", err)
		}
	}
}
// Any interactions with shortcuts, modals, or interactive components (such as buttons, select menus, and datepickers)
// [/interactivity]
func Interactivity(w http.ResponseWriter, r *http.Request) {
	var env Environment
	w, r, env = setupHttpRequest(w, r)
	slackClient := SlackClient{env.slackSecret, env.slackToken, env.botToken}


	var interactionCallback slack.InteractionCallback
	if len(r.Form["payload"]) == 0 {
		log.Fatalln("Empty payload, please try again later.")
	}
	err := json.Unmarshal([]byte(r.Form["payload"][0]), &interactionCallback)
	if err != nil {
		log.Fatalf("json.Unmarshal: %v", err)
	}

	message, err := handleInteractivityRequest(env, interactionCallback)
	if err != nil {
		fmt.Printf("handleInteractivityRequest: %v", err)
	}

	if message != nil {
		err = slackClient.postMessage(message)
		if err != nil {
			log.Fatalln(err)
		}
	}
}
// Load external data in select menus
// [/selectmenus]
func SelectMenus(w http.ResponseWriter, r *http.Request) {
	var env Environment
	w, r, env = setupHttpRequest(w, r)

	gonduitClient := gonduitDial(env)
	
	var resOption slack.DialogInputSelect
	var resSelect slack.InteractionCallback
	
	if len(r.Form["payload"]) == 0 {
		log.Fatalln("Empty payload, please try again later.")
	}
	err := json.Unmarshal([]byte(r.Form["payload"][0]), &resSelect)
	if err != nil {
		log.Fatalf("json.Unmarshal: %v", err)
	}

	if strings.HasPrefix(resSelect.CallbackID, "DialogCreateTaskSubmitted") {
		if resSelect.Name == "severity" {
			resOption = severityOptions(gonduitClient, resSelect)
		} else if resSelect.Name == "assignee" {
			resOption = assigneeOptions(gonduitClient, resSelect)
		} 
	} else if strings.HasPrefix(resSelect.CallbackID, "DialogRequestTagSubmitted") {
		if resSelect.Name == "project" {
			resOption = projectOptions(gonduitClient, resSelect)
		}
	}

	if err := json.NewEncoder(w).Encode(resOption); err != nil {
		log.Fatalf("json.Marshal: %v", err)
	}
}

func setupHttpRequest(w http.ResponseWriter, r *http.Request) (http.ResponseWriter, *http.Request, Environment) {
	env := setup(r.Context())

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalf("Couldn't read request body: %v", err)
	}
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	if r.Method != "POST" {
		http.Error(w, "Only POST requests are accepted", 405)
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Couldn't parse form", 400)
		log.Fatalf("ParseForm: %v", err)
	}

	// Reset r.Body as ParseForm depletes it by reading the io.ReadCloser.
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	result, err := verifyWebHook(r, env.slackSecret)
	if err != nil {
		log.Fatalf("verifyWebhook: %v", err)
	}
	if !result {
		log.Fatalf("signatures did not match.")
	}
	w.Header().Set("Content-Type", "application/json")

	return w, r, env
}

func makeSearchRequest(env Environment, query string, triggerID string) (*slack.Msg, error) {
	gonduitClient := gonduitDial(env)
	slackClient := SlackClient{env.slackSecret, env.slackToken, env.botToken}

	message := &slack.Msg{}
	var err error

	if strings.HasPrefix(strings.ToUpper(query), "T") {
		message, err = requestManiphestDetail(slackClient, gonduitClient, query)
		if err != nil {
			return message, err
		}
	}

	if isCreateTask(query) {
		message, err = openDialogRequestTag(slackClient, triggerID)
		if err != nil {
			return message, err
		}
	}

	if isEditRevision(query) {
		message, err = openDialogEditRevision(slackClient, triggerID)
		if err != nil {
			return message, err
		}
	}

	return message, err
}

func handleInteractivityRequest(env Environment, interactionCallback slack.InteractionCallback) (*slack.Msg, error) {
	gonduitClient := gonduitDial(env)
	slackClient := SlackClient{env.slackSecret, env.slackToken, env.botToken}

	message := &slack.Msg{}
	var err error
	callbackID := interactionCallback.CallbackID
	callbackType := string(interactionCallback.Type)
	if isDialogRequestTag(callbackType, callbackID) {
		tagName := interactionCallback.DialogSubmissionCallback.Submission["project"]

		message = &slack.Msg {
			Channel: interactionCallback.Channel.ID,
			Text: fmt.Sprintf("Create new task for %v", tagName),
			Username: "phabricator",
			Attachments: []slack.Attachment{
				{
					Fallback: "Please try again later.",
					CallbackID: "ContinueCreateTask",
					Actions: []slack.AttachmentAction {
						{
							Name: "create_task",
							Text: "Continue",
							Style: "primary",
							Type: "button",
							Value: "continue",
							Confirm: &slack.ConfirmationField{
								Title: "Continue",
								OkText: "Yes",
								DismissText: "No",
							},
						},
						{
							Name: "create_task",
							Text: "Cancel",
							Type: "button",
							Value: "cancel",
							Confirm: &slack.ConfirmationField{
								Title: "Cancel",
								OkText: "Yes",
								DismissText: "No",
							},
						},
					},
				},
			},	
		}

		return message, nil
	} else if isDialogCreateTask(callbackType, callbackID) {
		var assignee string
		tagPHID := getTagPHIDFromName(gonduitClient, strings.TrimSpace(strings.Split(callbackID, ":-")[1]))
		severity := 90

		if interactionCallback.DialogSubmissionCallback.Submission["severity"] != "" {
			severity, _ = strconv.Atoi(interactionCallback.DialogSubmissionCallback.Submission["severity"])
		}
		if interactionCallback.DialogSubmissionCallback.Submission["assignee"] != "" {
			assignee = interactionCallback.DialogSubmissionCallback.Submission["assignee"]
		}
		var resCreateTask ManiphestCreateTaskResponse
		if assignee == "" {
			reqCreateTask := &ManiphestCreateTaskRequest {
				Title: interactionCallback.DialogSubmissionCallback.Submission["title"],
				Description: interactionCallback.DialogSubmissionCallback.Submission["description"],
				ViewPolicy: "users",
				ProjectPHIDs: []string{tagPHID},
				Priority: severity,
			}
			err = gonduitClient.Call("maniphest.createtask", reqCreateTask, &resCreateTask)
		} else {
			if interactionCallback.DialogSubmissionCallback.Submission["title"] == "" {
				message = setMessage(interactionCallback.Channel.ID, "An error has been occurred when create new task", err.Error())
				return message, nil
			}
			if interactionCallback.DialogSubmissionCallback.Submission["description"] == "" {
				message = setMessage(interactionCallback.Channel.ID, "An error has been occurred when create new task", err.Error())
				return message, nil
			}
			reqCreateTask := &ManiphestCreateTaskRequestWithAssignee {
				Title: interactionCallback.DialogSubmissionCallback.Submission["title"],
				Description: interactionCallback.DialogSubmissionCallback.Submission["description"],
				ViewPolicy: "users",
				OwnerPHID: assignee,
				ProjectPHIDs: []string{tagPHID},
				Priority: severity,
			}
			err = gonduitClient.Call("maniphest.createtask", reqCreateTask, &resCreateTask)
		}
		if err != nil {
			message = setMessage(interactionCallback.Channel.ID, "An error has been occurred when create new task", err.Error())
			return message, nil
		}

		if resCreateTask.ID == "" {
			message = setMessage(interactionCallback.Channel.ID, "Failed to create new task", "Please try again later")
			return message, nil
		} else {
			timeInt64, _ := strconv.ParseInt(resCreateTask.DateCreated, 10, 64)
			t := time.Unix(timeInt64, 0)
			created := t.Format("January 2, 2006 - 3:04 PM")
		
			message = &slack.Msg{
				ResponseType: "in_channel",
				Channel: interactionCallback.Channel.ID,
				Username: "phabricator",
				Text:         fmt.Sprintf("https://phabricator.sirclo.com/T%s", resCreateTask.ID),
				Attachments: []slack.Attachment{
					{
						Title: resCreateTask.Title,
						TitleLink: fmt.Sprintf("https://phabricator.sirclo.com/T%s", resCreateTask.ID),
						Fields: []slack.AttachmentField{
							{
								Title: "Description",
								Value: resCreateTask.Description,
								Short: false,
							},
							{
								Title: "Status",
								Value: resCreateTask.Status,
								Short: false,
							},
							{
								Title: "Priority",
								Value: resCreateTask.Priority,
								Short: false,
							},
							{
								Title: "Created",
								Value: created,
								Short: false,
							},
						},
					},
				},
			}
			return message, nil
		}
	} else if isDialogEditRevision(callbackType, callbackID) {
		taskID, err := strconv.Atoi(interactionCallback.DialogSubmissionCallback.Submission["task"])
		if err != nil {
			message = setMessage(interactionCallback.Channel.ID, "Failed to edit revision", "Task id can only contain numbers. Please enter a valid task id")
			return message, nil
		}
		diffID, err := strconv.Atoi(interactionCallback.DialogSubmissionCallback.Submission["diff"])
		if err != nil {
			message = setMessage(interactionCallback.Channel.ID, "Failed to edit revision", "Differential id can only contain numbers. Please enter a valid differential id")
			return message, nil
		}
		remindedID := interactionCallback.DialogSubmissionCallback.Submission["target"]

		taskPHID := getManiphestPHIDFromID(gonduitClient, taskID)
		if taskPHID == "" {
			message = setMessage(interactionCallback.Channel.ID, "Failed to edit revision", "Task not found. Please enter a valid task id")
			return message, nil
		}
		diffPHID := getDifferentialRevisionPHIDFromID(gonduitClient, diffID)
		if diffPHID == "" {
			message = setMessage(interactionCallback.Channel.ID, "Failed to edit revision", "Differential not found. Please enter a valid differential id")
			return message, nil
		}

		reqEditRevision := &DifferentialRevisionEditRequest {
			Transactions: []DifferentialRevisionEditTransaction {
				{
					Type: "tasks.add",
					Value: []string{taskPHID},
				},
			},
			ObjectIdentifier: diffPHID,
		}
		var resEditRevision DifferentialRevisionEditResponse
		err = gonduitClient.Call("differential.revision.edit", reqEditRevision, &resEditRevision)
		if err != nil {
			message = setMessage(interactionCallback.Channel.ID, "An error has been occurred when edit revision", err.Error())
			return message, nil
		}

		if remindedID != "" {
			var remindedType, remindedName string
			if strings.HasPrefix(remindedID, "U") {
				remindedType = "user"
				remindedName = getUserNameFromID(slackClient, remindedID)
			} 
			if strings.HasPrefix(remindedID, "C") || strings.HasPrefix(remindedID, "G") {
				remindedType = "channel"
				remindedName = getChannelNameFromID(slackClient, remindedID)
			}
			if remindedName != "" {
				err = slackClient.addReminders(fmt.Sprintf("Please check the Code Review https://phabricator.sirclo.com/D%v", diffID), "1 hour", remindedType, remindedID)
				if err != nil {
					message = setMessage(interactionCallback.Channel.ID, "An error has been occurred when set reminders", err.Error())
					return message, nil
				}
				message = setMessage(interactionCallback.Channel.ID, fmt.Sprintf("https://phabricator.sirclo.com/D%v", diffID), fmt.Sprintf("Successfully attach [D%v] to [T%v], and have set reminders for %v '%v'.", diffID, taskID, remindedType, remindedName))
				return message, nil
			}

			message = setMessage(interactionCallback.Channel.ID, fmt.Sprintf("https://phabricator.sirclo.com/D%v", diffID), fmt.Sprintf("Successfully attach [D%v] to [T%v], but failed to set reminders.", diffID, taskID))
			return message, err
		} 

		message = setMessage(interactionCallback.Channel.ID, fmt.Sprintf("https://phabricator.sirclo.com/D%v", diffID), fmt.Sprintf("Successfully attach [D%v] to [T%v]", diffID, taskID))
		return message, nil
	} else if isContinueCreateTask(callbackType, callbackID) {
		triggerID := interactionCallback.TriggerID

		actionName := (*interactionCallback.ActionCallback.AttachmentActions[0]).Name
		actionValue := (*interactionCallback.ActionCallback.AttachmentActions[0]).Value

		if actionName == "create_task" {
			if actionValue == "continue" {
				tagName := strings.Split(interactionCallback.OriginalMessage.Text, "for")[1]
				tagName = strings.TrimSpace(tagName)
				
				message, err := openDialogCreateManiphest(slackClient, triggerID, tagName)
				if err != nil {
					message.Channel = interactionCallback.Channel.ID
					return message, err
				}

				message = &slack.Msg{
					Channel: interactionCallback.Channel.ID,
					Timestamp: interactionCallback.MessageTs,
				}

				err = slackClient.chatDelete(message)
				if err != nil {
					message = setMessage(interactionCallback.Channel.ID, "An error has been occurred when send HTTP request", err.Error())
					return message, err
				}
			}
			if actionValue == "cancel" {
				reqEditMessage, _ := json.Marshal(map[string]string{
					"replace_original": "true",
					"text": "Create task action canceled.",
				})
				
				resEditMessage, err := http.Post(interactionCallback.ResponseURL, "application/json", bytes.NewBuffer(reqEditMessage))
				if err != nil {
					message = setMessage(interactionCallback.Channel.ID, "An error has been occurred while canceling the task creation", err.Error())
					return message, err
				}
				defer resEditMessage.Body.Close()
			}
		}
	}

	return message, err
}

func severityOptions(gonduitClient *gonduit.Conn, resSelect slack.InteractionCallback) slack.DialogInputSelect {
	var resOption slack.DialogInputSelect
	var resSeverity ManiphestPriorityResponse

	reqSeverity := &EmptyGonduitRequest{}
	err := gonduitClient.Call("maniphest.priority.search", reqSeverity, &resSeverity)
	if err != nil {
		log.Fatalln(err)
	}

	if len(resSeverity.Data) > 0 {
		if resSelect.Value != "" {
			for k := range resSeverity.Data {
				if strings.Contains(strings.ToLower(resSeverity.Data[k].Name), strings.ToLower(resSelect.Value)) {
					resOption.Options = append(resOption.Options, slack.DialogSelectOption{
						Label: resSeverity.Data[k].Name,
						Value: strconv.Itoa(resSeverity.Data[k].Value),
					})
				}
			}
		} else {
			for k := range resSeverity.Data {
				resOption.Options = append(resOption.Options, slack.DialogSelectOption{
					Label: resSeverity.Data[k].Name,
					Value: strconv.Itoa(resSeverity.Data[k].Value),
				})
			}
		}
	} 
	return resOption
}

func assigneeOptions(gonduitClient *gonduit.Conn, resSelect slack.InteractionCallback) slack.DialogInputSelect {
	var resOption slack.DialogInputSelect
	var listUserMember, listUserOthers, listUserNotMember []slack.DialogSelectOption

	tagName := strings.Split(resSelect.CallbackID, ":-")[1]
	tagName = strings.TrimSpace(tagName)

	reqUser := &ProjectSearchRequest{
		Constraints: ProjectSearchConstraint{
			Name: tagName,
			Icons: []string{"bugs", "project"},
		},
		Attachments: ProjectSearchAttachment{
			Members: true,
		},
	}
	var resUser ProjectSearchResponse
	err := gonduitClient.Call("project.search", reqUser, &resUser)
	if err != nil {
		log.Fatalln(err)
	}

	listPHIDUsers := []string{}
	var resMember UserSearchResponse
	var resOthers UserSearchResponse
	if len(resUser.Data[0].Attachments.Members.Members) > 0 {
		for k := range resUser.Data[0].Attachments.Members.Members {
			listPHIDUsers = append(listPHIDUsers, resUser.Data[0].Attachments.Members.Members[k].PHID)
		}
		
		if resSelect.Value != "" {
			reqMember := &UserSearchRequestWithPHID {
				Constraints: UserSearchConstraintWithPHID{
					PHIDs: listPHIDUsers,
					Query: fmt.Sprintf("~%v", resSelect.Value),
				},
			}
			err := gonduitClient.Call("user.search", reqMember, &resMember)
			if err != nil {
				log.Fatalln(err)
			}
		} else {
			reqMember := &UserSearchRequestWithPHID {
				Constraints: UserSearchConstraintWithPHID{
					PHIDs: listPHIDUsers,
				},
			}
			err := gonduitClient.Call("user.search", reqMember, &resMember)
			if err != nil {
				log.Fatalln(err)
			}
		}

		for m := range resMember.Data {
			listUserMember = append(listUserMember, slack.DialogSelectOption{
				Label: resMember.Data[m].Fields.Username,
				Value: resMember.Data[m].PHID,
			})
		}
	}	
	
	if resSelect.Value != "" {
		reqOthers := &UserSearchRequest {
			Constraints: UserSearchConstraint{
				Query: fmt.Sprintf("~%v", resSelect.Value),
			},
		}
		err = gonduitClient.Call("user.search", reqOthers, &resOthers)
		if err != nil {
			log.Fatalln(err)
		}
	} else {
		reqOthers := &EmptyGonduitRequest{}
		err = gonduitClient.Call("user.search", reqOthers, &resOthers)
		if err != nil {
			log.Fatalln(err)
		}
	}

	for m := range resOthers.Data {
		listUserOthers = append(listUserOthers, slack.DialogSelectOption{
			Label: resOthers.Data[m].Fields.Username,
			Value: resOthers.Data[m].PHID,
		})
	}

	if len(listUserMember) > 0 {
		listUserNotMember = getPeopleNotInGroup(listUserOthers, listUserMember)
		if len(listUserNotMember) > (limitQuery - len(listUserMember)) {
			listUserNotMember = listUserNotMember[:(limitQuery - len(listUserMember))]
		}

		resOption = slack.DialogInputSelect{
			OptionGroups: []slack.DialogOptionGroup{
				{
					Label: "Project Members",
					Options: listUserMember,
				},
				{
					Label: "Others",
					Options: listUserNotMember,
				},
			},
		}
	} else {
		if len(listUserOthers) > limitQuery {
			listUserNotMember = listUserOthers[:limitQuery]
		} else {
			listUserNotMember = listUserOthers
		}

		resOption = slack.DialogInputSelect{
			Options: listUserNotMember,
		}
	}

	return resOption
}

func projectOptions(gonduitClient *gonduit.Conn, resSelect slack.InteractionCallback) slack.DialogInputSelect {
	var resOption slack.DialogInputSelect
	var resTag ProjectSearchResponse

	if resSelect.Value != "" {
		projectIconNeeded := []string{"bugs", "project"}
		reqTag := &ProjectSearchRequest {
			QueryKey: "active",
			Order: "newest",
			Constraints: ProjectSearchConstraint{
				Icons: projectIconNeeded,
				Query: fmt.Sprintf("~%v", resSelect.Value),
			},
		}
		err := gonduitClient.Call("project.search", reqTag, &resTag)
		if err != nil {
			log.Fatalln(err)
		} else {
			for k := range resTag.Data {
				var tagName string
				if len(resTag.Data[k].Fields.Name) > maxCharacterLabel {
					tagName = fmt.Sprintf("%v...", resTag.Data[k].Fields.Name[:maxCharacterLabel])
				} else {
					tagName = resTag.Data[k].Fields.Name
				}
				resOption.Options = append(resOption.Options, slack.DialogSelectOption{
					Label: tagName,
					Value: tagName,
				})
			}
		}
	} else {
		reqTag := &ProjectSearchRequest {
			QueryKey: "active",
			Order: "newest",
			Constraints: ProjectSearchConstraint{
				Icons: []string{"bugs", "project"},
			},
		}
		err := gonduitClient.Call("project.search", reqTag, &resTag)
		if err != nil {
			log.Fatalln(err)
		} else {
			for k := range resTag.Data {
				var tagName string
				if len(resTag.Data[k].Fields.Name) > maxCharacterLabel {
					tagName = fmt.Sprintf("%v...", resTag.Data[k].Fields.Name[:maxCharacterLabel])
				} else {
					tagName = resTag.Data[k].Fields.Name
				}
				resOption.Options = append(resOption.Options, slack.DialogSelectOption{
					Label: tagName,
					Value: tagName,
				})
			}
		}
	}

	return resOption
}

func setMessage(channelID string, text string, subtext string) *slack.Msg {
	return &slack.Msg{
		Channel: channelID,
		ResponseType: "in_channel",
		Text: text,
		Username: "phabricator",
		Attachments: []slack.Attachment{
			{
				Text: subtext,
			},
		},
	}
}

func requestManiphestDetail(slackClient SlackClient, gonduitClient *gonduit.Conn, query string) (message *slack.Msg, err error) {
	maniphestID, err := strconv.Atoi(query[1:])
	if err != nil {
		message = setMessage("", "Please enter a valid task id", "Task id can only contain numbers")
		return message, nil
	}

	req := requests.ManiphestSearchRequest{
		Constraints: &requests.ManiphestSearchConstraints{
			IDs: []int{maniphestID},
		},
	}

	res, err := gonduitClient.ManiphestSearch(req)
	if err != nil {
		message = setMessage("", "An error has been occurred when request Maniphest Search", err.Error())
		return message, err
	}

	if len(res.Data) <= 0 {
		message = setMessage("", "Task not found", "Please refine your search")
		return message, nil
	}

	t := time.Time(res.Data[0].Fields.DateCreated)
	created := t.Format("2006-01-02")

	t = time.Time(res.Data[0].Fields.DateModified)
	lastModified := t.Format("2006-01-02")

	message = &slack.Msg{
		ResponseType: "in_channel",
		Text:         fmt.Sprintf("https://phabricator.sirclo.com/T%s", query[1:]),
		Attachments: []slack.Attachment{
			{
				Title:     fmt.Sprintf("%s", res.Data[0].Fields.Name),
				TitleLink: fmt.Sprintf("https://phabricator.sirclo.com/T%s", query[1:]),
				Fields: []slack.AttachmentField{
					{
						Title: "Description",
						Value: res.Data[0].Fields.Description.Raw,
						Short: false,
					},
					{
						Title: "Status",
						Value: res.Data[0].Fields.Status.Value,
						Short: false,
					},
					{
						Title: "Created",
						Value: created,
						Short: false,
					},
					{
						Title: "Last Updated",
						Value: lastModified,
						Short: false,
					},
				},
			},
		},
	}
	return message, nil
}

func openDialogRequestTag(slackClient SlackClient, triggerID string) (*slack.Msg, error) {
	var err error
	var message *slack.Msg
	dialog := slack.DialogTrigger{
		TriggerID: triggerID,
		Dialog: slack.Dialog{
			CallbackID: "DialogRequestTagSubmitted",
			Title: "Create New Task",
			SubmitLabel: "Request",
			State: "Limo",
			Elements: []slack.DialogElement{
				slack.DialogInputSelect{
					DataSource: "external",
					DialogInput: slack.DialogInput{
						Type:        "select",
						Label:       "Project or Tag Name",
						Name:        "project",
						Placeholder: "Choose a Project or tag",
					},
				},
			},
		},
	}

	message, err = slackClient.openDialog(dialog)
	return message, err
}

func openDialogCreateManiphest(slackClient SlackClient, triggerID string, tagName string) (*slack.Msg, error) {
	var err error
	var message *slack.Msg
	dialog := slack.DialogTrigger{
		TriggerID: triggerID,
		Dialog: slack.Dialog{
			CallbackID: fmt.Sprintf("DialogCreateTaskSubmitted :- %v", tagName),
			Title: "Create New Task",
			SubmitLabel: "Request",
			State: "Limo",
			Elements: []slack.DialogElement{
				slack.TextInputElement{
					Hint:  "Please enter the task title",
					DialogInput: slack.DialogInput{
						Type:        "text",
						Label:       "Title",
						Name:        "title",
						Placeholder: "Task title",
					},
				},
				slack.TextInputElement{
					Hint:  "Please enter the task description",
					DialogInput: slack.DialogInput{
						Type:  "textarea",
						Label: "Description",
						Name:  "description",
						Placeholder: "Task description",
					},
				},
				slack.DialogInputSelect{
					DataSource: "external",
					Hint:  "Default severity is 'Needs Triage'",
					DialogInput: slack.DialogInput{
						Optional: true,
						Type:        "select",
						Label:       "Severity",
						Name:        "severity",
						Placeholder: "Choose a task severity",
					},
				},
				slack.DialogInputSelect{
					DataSource: "external",
					Hint:  "Default assignee is 'phabulous (Phabulous Bot)'",
					DialogInput: slack.DialogInput{
						Optional: true,
						Type:        "select",
						Label:       "Assignee",
						Name:        "assignee",
						Placeholder: "Choose a task assignee",
					},
				},
			},
		},
	}

	message, err = slackClient.openDialog(dialog)
	return message, err
}

func openDialogEditRevision(slackClient SlackClient, triggerID string) (*slack.Msg, error) {
	var err error
	var message *slack.Msg
	dialog := slack.DialogTrigger{
		TriggerID: triggerID,
		Dialog: slack.Dialog{
			CallbackID: "DialogEditRevisionSubmitted",
			Title: "Edit Revision",
			SubmitLabel: "Request",
			State: "Limo",
			Elements: []slack.DialogElement{
				slack.TextInputElement{
					Hint:  "Please enter the task id",
					DialogInput: slack.DialogInput{
						Type:        "text",
						Label:       "Task",
						Name:        "task",
						Placeholder: "Task ID",
					},
				},
				slack.TextInputElement{
					Hint:  "Please enter the differential revision id",
					DialogInput: slack.DialogInput{
						Type:        "text",
						Label:       "Differential",
						Name:        "diff",
						Placeholder: "Differential ID",
					},
				},
				slack.DialogInputSelect{
					DataSource: "conversations",
					Hint:  "Please choose channel or user to be reminded.",
					DialogInput: slack.DialogInput{
						Optional: true,
						Type:        "select",
						Label:       "Reminders",
						Name:        "target",
						Placeholder: "Choose Channel or user",
					},
				},
			},
		},
	}

	message, err = slackClient.openDialog(dialog)
	return message, err
}

func gonduitDial(env Environment) *gonduit.Conn {
	gonduitClient, err := gonduit.Dial(
		"https://phabricator.sirclo.com",
		&core.ClientOptions{
			APIToken: env.phabAPIToken,
		},
	)

	if ce, ok := err.(*core.ConduitError); ok {
		log.Fatal("code: " + ce.Code() + "and info: " + ce.Info())
	}

	// Or, use the built-in utility function:
	if core.IsConduitError(err) {
		log.Fatal(err)
	}

	return gonduitClient
}

func sendHttpPostRequest(slackClient SlackClient, url string, payload interface{}) error {
	jsonPayload, _ := json.Marshal(payload)
	bearerToken := "Bearer " + slackClient.botToken

	HTTPClient := &http.Client{}
	request, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	request.Header.Add("Authorization", bearerToken)
	
	response, err := HTTPClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return nil
}

func getPeopleNotInGroup(a, b []slack.DialogSelectOption) []slack.DialogSelectOption {
	target := map[string]bool{}
    for x, _ := range b {
		target[b[x].Label] = true
	}
	
    result := []slack.DialogSelectOption{}
    for x, _ := range a {
        if _, ok := target[a[x].Label]; !ok {
            result = append(result, slack.DialogSelectOption{
				Label: a[x].Label,
				Value: a[x].Value,
			})
        }
	}

    return result
}

func getTagPHIDFromName(gonduitClient *gonduit.Conn, tagName string) string {
	reqTag := &ProjectSearchRequest{
		Constraints: ProjectSearchConstraint{
			Name: tagName,
			Icons: []string{"bugs", "project"},
		},
	}
	var resTag ProjectSearchResponse
	err := gonduitClient.Call("project.search", reqTag, &resTag)

	if err == nil && len(resTag.Data) > 0 {
		return resTag.Data[0].PHID
	}

	return ""
}

func getManiphestPHIDFromID(gonduitClient *gonduit.Conn, id int) string {
	req := requests.ManiphestSearchRequest{
		Constraints: &requests.ManiphestSearchConstraints{
			IDs: []int{id},
		},
	}
	res, err := gonduitClient.ManiphestSearch(req)

	if err == nil && len(res.Data) > 0 {
		return res.Data[0].PHID
	}

	return "" 
}

func getDifferentialRevisionPHIDFromID(gonduitClient *gonduit.Conn, id int) string {
	req := &DifferentialRevisionSearchRequest {
		Constraints: DifferentialRevisionSearchConstraints {
			IDs: []int{id},
		},
	}
	var res DifferentialRevisionSearchResponse
	err := gonduitClient.Call("differential.revision.search", req, &res)

	if err == nil && len(res.Data) > 0 {
		return res.Data[0].PHID
	}

	return "" 
}

func getChannelNameFromID(slackClient SlackClient, id string) string {
	channelList, err := slackClient.conversationLists()
	if err != nil {
		log.Fatalf("Couldn't read request body: %v", err)
	} else {
		for _, channel := range channelList.Channels {
			if id == channel.ID {
				return channel.Name
			}
		}
	}

	return ""
}

func getUserNameFromID(slackClient SlackClient, id string) string {
	userList, err := slackClient.userLists()
	if err != nil {
		log.Fatalf("Couldn't read request body: %v", err)
	} else {
		for _, user := range userList.Members {
			if id == user.ID {
				return user.Name
			}
		}
	}

	return ""
}

func isCreateTask(query string) bool {
	query = strings.ToLower(query)
	if query == "create" || query == "create task" || query == "createtask" {
		return true
	}
	return false
}

func isEditRevision(query string) bool {
	query = strings.ToLower(query)
	if query == "edit revision" || query == "editrevision" {
		return true
	}
	return false
}

func isDialogRequestTag(callbackType string, callbackID string) bool {
	if callbackType == "dialog_submission" && callbackID == "DialogRequestTagSubmitted" {
		return true
	}
	return false
}

func isDialogCreateTask(callbackType string, callbackID string) bool {
	if callbackType == "dialog_submission" && strings.HasPrefix(callbackID, "DialogCreateTaskSubmitted") {
		return true
	}
	return false
}

func isDialogEditRevision(callbackType string, callbackID string) bool {
	if callbackType == "dialog_submission" && callbackID == "DialogEditRevisionSubmitted" {
		return true
	}
	return false
}

func isContinueCreateTask(callbackType string, callbackID string) bool {
	if callbackType == "interactive_message" && callbackID == "ContinueCreateTask" {
		return true
	}
	return false
}

// verifyWebHook verifies the request signature.
// See https://api.slack.com/docs/verifying-requests-from-slack.
func verifyWebHook(r *http.Request, slackSigningSecret string) (bool, error) {
	timeStamp := r.Header.Get(slackRequestTimestampHeader)
	slackSignature := r.Header.Get(slackSignatureHeader)

	if timeStamp == "" || slackSignature == "" {
		return false, fmt.Errorf("timestamp or slack signature is empty")
	}

	t, err := strconv.ParseInt(timeStamp, 10, 64)
	if err != nil {
		return false, fmt.Errorf("strconv.ParseInt(%s): %v", timeStamp, err)
	}

	if ageOk, age := checkTimestamp(t); !ageOk {
		return false, &oldTimeStampError{fmt.Sprintf("checkTimestamp(%v): %v %v", t, ageOk, age)}
		// return false, fmt.Errorf("checkTimestamp(%v): %v %v", t, ageOk, age)
	}

	if timeStamp == "" || slackSignature == "" {
		return false, fmt.Errorf("either timeStamp or signature headers were blank")
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return false, fmt.Errorf("ioutil.ReadAll(%v): %v", r.Body, err)
	}

	// Reset the body so other calls won't fail.
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	baseString := fmt.Sprintf("%s:%s:%s", version, timeStamp, body)

	signature := getSignature([]byte(baseString), []byte(slackSigningSecret))

	trimmed := strings.TrimPrefix(slackSignature, fmt.Sprintf("%s=", version))
	signatureInHeader, err := hex.DecodeString(trimmed)

	if err != nil {
		return false, fmt.Errorf("hex.DecodeString(%v): %v", trimmed, err)
	}

	return hmac.Equal(signature, signatureInHeader), nil
}

func getSignature(base []byte, secret []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write(base)

	return h.Sum(nil)
}

// Arbitrarily trusting requests time stamped less than 5 minutes ago.
func checkTimestamp(timeStamp int64) (bool, time.Duration) {
	t := time.Since(time.Unix(timeStamp, 0))

	return t.Minutes() <= 5, t
}

