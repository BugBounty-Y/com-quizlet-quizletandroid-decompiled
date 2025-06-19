package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.db.billing.model.DBSubscription;
import com.quizlet.db.data.models.base.AssociationNames;
import com.quizlet.db.data.models.persisted.DBAnswer;
import com.quizlet.db.data.models.persisted.DBBookmark;
import com.quizlet.db.data.models.persisted.DBDiagramShape;
import com.quizlet.db.data.models.persisted.DBEnteredSetPassword;
import com.quizlet.db.data.models.persisted.DBFolder;
import com.quizlet.db.data.models.persisted.DBGroup;
import com.quizlet.db.data.models.persisted.DBGroupFolder;
import com.quizlet.db.data.models.persisted.DBGroupMembership;
import com.quizlet.db.data.models.persisted.DBGroupSet;
import com.quizlet.db.data.models.persisted.DBImage;
import com.quizlet.db.data.models.persisted.DBImageRef;
import com.quizlet.db.data.models.persisted.DBQuestionAttribute;
import com.quizlet.db.data.models.persisted.DBSchool;
import com.quizlet.db.data.models.persisted.DBSelectedTerm;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBStudySetting;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.DBUserStudyable;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
/* loaded from: classes2.dex */
public class ModelWrapper {
    List<DBAnswer> answers;
    List<DBBookmark> bookmarks;
    List<DBDiagramShape> diagramShapes;
    List<DBEnteredSetPassword> enteredSetPasswords;
    List<DBFolder> folders;
    List<DBGroupFolder> groupFolders;
    List<DBGroupMembership> groupMemberships;
    List<DBGroupSet> groupSets;
    List<DBGroup> groups;
    List<DBImageRef> imageRefs;
    List<DBImage> images;
    List<ProfileImage> profileImages;
    List<DBQuestionAttribute> questionAttributes;
    List<DBSchool> schools;
    List<DBSelectedTerm> selectedTerms;
    List<DBSession> sessions;
    List<DBStudySet> sets;
    List<DBStudySetting> studySettings;
    List<DBSubscription> subscriptions;
    List<DBTerm> terms;
    List<DBUserStudyable> userStudyables;
    List<DBUser> users;

    public List<DBAnswer> getAnswers() {
        return this.answers;
    }

    public List<DBBookmark> getBookmarks() {
        return this.bookmarks;
    }

    public List<DBDiagramShape> getDiagramShapes() {
        return this.diagramShapes;
    }

    public List<DBEnteredSetPassword> getEnteredSetPasswords() {
        return this.enteredSetPasswords;
    }

    public List<DBFolder> getFolders() {
        return this.folders;
    }

    public List<DBGroupFolder> getGroupFolders() {
        return this.groupFolders;
    }

    public List<DBGroupMembership> getGroupMemberships() {
        return this.groupMemberships;
    }

    public List<DBGroupSet> getGroupSets() {
        return this.groupSets;
    }

    public List<DBGroup> getGroups() {
        return this.groups;
    }

    public List<DBImageRef> getImageRefs() {
        return this.imageRefs;
    }

    public List<DBImage> getImages() {
        return this.images;
    }

    public List<ProfileImage> getProfileImages() {
        return this.profileImages;
    }

    public List<DBQuestionAttribute> getQuestionAttributes() {
        return this.questionAttributes;
    }

    public List<DBSchool> getSchools() {
        return this.schools;
    }

    public List<DBSelectedTerm> getSelectedTerms() {
        return this.selectedTerms;
    }

    public List<DBSession> getSessions() {
        return this.sessions;
    }

    public List<DBStudySet> getStudySets() {
        return this.sets;
    }

    public List<DBStudySetting> getStudySettings() {
        return this.studySettings;
    }

    public List<DBSubscription> getSubscriptions() {
        return this.subscriptions;
    }

    public List<DBTerm> getTerms() {
        return this.terms;
    }

    public List<DBUserStudyable> getUserStudyables() {
        return this.userStudyables;
    }

    public List<DBUser> getUsers() {
        return this.users;
    }

    @JsonProperty("answer")
    public void setAnswers(List<DBAnswer> list) {
        this.answers = list;
    }

    @JsonProperty(DBBookmark.TABLE_NAME)
    public void setBookmarks(List<DBBookmark> list) {
        this.bookmarks = list;
    }

    @JsonProperty(DBDiagramShape.TABLE_NAME)
    public void setDiagramShapes(List<DBDiagramShape> list) {
        this.diagramShapes = list;
    }

    @JsonProperty("enteredSetPassword")
    public void setEnteredSetPasswords(List<DBEnteredSetPassword> list) {
        this.enteredSetPasswords = list;
    }

    @JsonProperty("folder")
    public void setFolders(List<DBFolder> list) {
        this.folders = list;
    }

    @JsonProperty("classFolder")
    public void setGroupFolders(List<DBGroupFolder> list) {
        this.groupFolders = list;
    }

    @JsonProperty(AssociationNames.CLASS_MEMBERSHIP)
    public void setGroupMemberships(List<DBGroupMembership> list) {
        this.groupMemberships = list;
    }

    @JsonProperty("classSet")
    public void setGroupSets(List<DBGroupSet> list) {
        this.groupSets = list;
    }

    @JsonProperty(AssociationNames.CLASS)
    public void setGroups(List<DBGroup> list) {
        this.groups = list;
    }

    @JsonProperty(DBImageRef.TABLE_NAME)
    public void setImageRefs(List<DBImageRef> list) {
        this.imageRefs = list;
    }

    @JsonProperty("image")
    public void setImages(List<DBImage> list) {
        this.images = list;
    }

    @JsonProperty("profileImage")
    public void setProfileImages(List<ProfileImage> list) {
        this.profileImages = list;
    }

    @JsonProperty("questionAttribute")
    public void setQuestionAttributes(List<DBQuestionAttribute> list) {
        this.questionAttributes = list;
    }

    @JsonProperty("school")
    public void setSchools(List<DBSchool> list) {
        this.schools = list;
    }

    @JsonProperty("selectedTerm")
    public void setSelectedTerms(List<DBSelectedTerm> list) {
        this.selectedTerms = list;
    }

    @JsonProperty("session")
    public void setSessions(List<DBSession> list) {
        this.sessions = list;
    }

    @JsonProperty("set")
    public void setSets(List<DBStudySet> list) {
        this.sets = list;
    }

    @JsonProperty("studySetting")
    public void setStudySettings(List<DBStudySetting> list) {
        this.studySettings = list;
    }

    @JsonProperty(DBSubscription.TABLE_NAME)
    public void setSubscriptions(List<DBSubscription> list) {
        this.subscriptions = list;
    }

    @JsonProperty("term")
    public void setTerms(List<DBTerm> list) {
        this.terms = list;
    }

    @JsonProperty(DBUserStudyable.TABLE_NAME)
    public void setUserStudyables(List<DBUserStudyable> list) {
        this.userStudyables = list;
    }

    @JsonProperty("user")
    public void setUsers(List<DBUser> list) {
        this.users = list;
    }
}
