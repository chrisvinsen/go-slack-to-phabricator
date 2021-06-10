package slack

import (
	"fmt"
	"log"
	"io/ioutil"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/slack-go/slack"
)

type SlackClient struct {
    slackSecret                 string
    slackToken                  string
    botToken                    string
}

func (s SlackClient) openDialog(dialog slack.DialogTrigger) (*slack.Msg, error) {
	var message *slack.Msg
	err := sendHttpPostRequest(s, "https://slack.com/api/dialog.open", dialog)
	if err != nil {
		message = setMessage("", "An error occurred while opening the dialog", err.Error())
	}
	return message, err
}

func (s SlackClient) postMessage(message *slack.Msg) error {
	err := sendHttpPostRequest(s, "https://slack.com/api/chat.postMessage", message)
	return err
}

func (s SlackClient) chatDelete(message *slack.Msg) error {
	err := sendHttpPostRequest(s, "https://slack.com/api/chat.delete", message)
	return err
}

func (s SlackClient) addReminders(text, time, remindedType, remindedID string) error {
	reqReminders := url.Values{
		"text": {text},
		"token": {s.slackToken},
		"time": {time},
		remindedType: {remindedID},
	}

	_, err := http.PostForm("https://slack.com/api/reminders.add", reqReminders)
	return err
}

func (s SlackClient) conversationLists() (ChannelSearchResponse, error) {
	var channelList ChannelSearchResponse
	bodyTypes := "public_channel,private_channel"
	reqURL := fmt.Sprintf("https://slack.com/api/conversations.list?token=%v&types=%v", s.botToken, bodyTypes)
	res, err := http.Get(reqURL)
	if err != nil {
		return channelList, err
	} 
	defer res.Body.Close()
	channelData, _ := ioutil.ReadAll(res.Body)
	err = json.Unmarshal([]byte(channelData), &channelList)
	return channelList, err
}

func (s SlackClient) userLists() (UserSearchResponse, error) {
	var userList UserSearchResponse
	reqURL := fmt.Sprintf("https://slack.com/api/users.list?token=%v", s.botToken)
	res, err := http.Get(reqURL)
	if err != nil {
		log.Fatalf("Couldn't request HTTP GET: %v", err)
		return userList, err
	}
	defer res.Body.Close()
	userData, _ := ioutil.ReadAll(res.Body)
	err = json.Unmarshal([]byte(userData), &userList)
	return userList, err
}

