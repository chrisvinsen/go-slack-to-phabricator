package slack

import "github.com/uber/gonduit/requests"


// Only contain Session
type EmptyGonduitRequest struct {
    requests.Request     
}

// Conduit - Maniphest Priority
type ManiphestPriorityResponse struct {
    Data []struct {
        Name                        string                      `json:"name"`
        Value                       int                         `json:"value"`
    }                                                           `json:"data"`
}

// Conduit - Project Search 
type ProjectSearchRequest struct {
    QueryKey                        string                      `json:"queryKey"`
    Constraints                     ProjectSearchConstraint     `json:"constraints"`
    Attachments                     ProjectSearchAttachment     `json:"attachments"`
    Order                           interface{}                 `json:"order"`
    requests.Request
}
type ProjectSearchConstraint struct {
    Name                            string                      `json:"name"`
    Icons                           []string                    `json:"icons"`
    Query                           string                      `json:"query"`
}
type ProjectSearchAttachment struct {
    Members                         bool                        `json:"members"`
}
type ProjectSearchResponse struct {
    Data []struct {
        ID                          int                         `json:"id"`
        PHID                        string                      `json:"phid"`
        Fields struct {
            Name                    string                      `json:"name"`
        }                                                       `json:"fields"`
        Attachments struct {
            Members struct {
                Members []struct {
                    PHID            string                      `json:"phid"`
                }                                               `json:"members"`
            }                                                   `json:"members"`
        }                                                       `json:"attachments"`
    }                                                           `json:"data"`
    Cursor struct {
        Limit                       interface{}                 `json:"limit"`
        Before                      interface{}                 `json:"before"`
        After                       interface{}                 `json:"after"`
    }                                                           `json:"cursor"`        
}

// Conduit - Maniphest Create Task
type ManiphestCreateTaskRequest struct {
    Title                           string                      `json:"title"`
    Description                     string                      `json:"description"`
    ViewPolicy                      string                      `json:"viewPolicy"`
    Priority                        int                         `json:"priority"`
    ProjectPHIDs                    []string                    `json:"projectPHIDs"`
    requests.Request
}
type ManiphestCreateTaskRequestWithAssignee struct {
    Title                           string                      `json:"title"`
    Description                     string                      `json:"description"`
    OwnerPHID                       string                      `json:"ownerPHID"`
    ViewPolicy                      string                      `json:"viewPolicy"`
    Priority                        int                         `json:"priority"`
    ProjectPHIDs                    []string                    `json:"projectPHIDs"`
    requests.Request
}
type ManiphestCreateTaskResponse struct {
    ID                              string                      `json:"id"`
    PHID                            string                      `json:"phid"`
    Status                          string                      `json:"status"`
    Priority                        string                      `json:"priority"`
    Title                           string                      `json:"title"`
    Description                     string                      `json:"description"`
    DateCreated                     string                      `json:"dateCreated"`
}

// Conduit - Differential Revision Search
type DifferentialRevisionSearchRequest struct {
    Constraints                     DifferentialRevisionSearchConstraints   `json:"constraints, differentialRevisionSearchConstraints"`
    requests.Request
}
type DifferentialRevisionSearchConstraints struct {
    IDs                             []int                       `json:"ids"`
}
type DifferentialRevisionSearchResponse struct {
    Data []struct {
        ID                          int                         `json:"id"`
        PHID                        string                      `json:"phid"`
    }                                                           `json:"data"`
}

// Conduit - Differential Revision Edit
type DifferentialRevisionEditRequest struct {
    Transactions                    []DifferentialRevisionEditTransaction    `json:"transactions"`
    ObjectIdentifier                string                                   `json:"objectIdentifier"`
    requests.Request
}
type DifferentialRevisionEditTransaction struct {
    Type                            string                      `json:"type"`
    Value                           []string                    `json:"value"`
}
type DifferentialRevisionEditResponse struct {
    Object struct {
        ID                          int                         `json:"id"`
        PHID                        string                      `json:"phid"`
    }                                                           `json:"object"`
    Transactions []struct {
        PHID                        string                      `json:"phid"`
    }                                                           `json:"transactions"`
}

// Conduit - Channel Search
type ChannelSearchResponse struct {
    Channels []struct {
        ID                          string                      `json:"id"`
        Name                        string                      `json:"name"`
    }                                                           `json:"channels"`
}

// Conduit - User Search
type UserSearchRequest struct {
    Constraints                     UserSearchConstraint        `json:"constraints"`
    requests.Request
}
type UserSearchConstraint struct {
    Query                           string                      `json:"query"`
}
type UserSearchRequestWithPHID struct {
    Constraints                     UserSearchConstraintWithPHID   `json:"constraints"`
    requests.Request
}
type UserSearchConstraintWithPHID struct {
    PHIDs                           []string                    `json:"phids"`
    Query                           string                      `json:"query"`
}
type UserSearchResponse struct {
    Data []struct {
        ID                          int                         `json:"id"`
        PHID                        string                      `json:"phid"`
        Fields struct {
            Username                string                      `json:"username"`
            RealName                string                      `json:"realName"`
        }                                                       `json:"fields"`
    }                                                           `json:"data"`
    Members []struct {
        ID                          string                      `json:"id"`
        Name                        string                      `json:"name"`
    }                                                           `json:"members"`
}

