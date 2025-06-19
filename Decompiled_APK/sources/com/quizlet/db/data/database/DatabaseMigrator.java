package com.quizlet.db.data.database;

import android.database.sqlite.SQLiteDatabase;
import com.comscore.streaming.ContentType;
import com.j256.ormlite.android.apptools.OrmLiteSqliteOpenHelper;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.table.TableUtils;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.quizlet.db.data.database.migration.Migration0049AddStudySettingTable;
import com.quizlet.db.data.database.migration.Migration0050AddSessionItemIdAndItemType;
import com.quizlet.db.data.database.migration.Migration0051AssignPersonIdToAnswers;
import com.quizlet.db.data.database.migration.Migration0052AddLocaleColumnsToUser;
import com.quizlet.db.data.database.migration.Migration0053AddLocaleColumnsToUser;
import com.quizlet.db.data.database.migration.Migration0054AddUserSettingsColumnsToUser;
import com.quizlet.db.data.database.migration.Migration0055AddCanChangeUsernameToUser;
import com.quizlet.db.data.database.migration.Migration0056ProfileImageIdToUser;
import com.quizlet.db.data.database.migration.Migration0057AddGroupLongTimestamp;
import com.quizlet.db.data.database.migration.Migration0058CopyGroupTimestampToLongField;
import com.quizlet.db.data.database.migration.Migration0059AddUserIsUnderAge;
import com.quizlet.db.data.database.migration.Migration0060AddImageTable;
import com.quizlet.db.data.database.migration.Migration0061AddUserNeedsChildDirectedTreatment;
import com.quizlet.db.data.database.migration.Migration0062AddNotificationColumnsToUser;
import com.quizlet.db.data.database.migration.Migration0063AddUserStudyableTable;
import com.quizlet.db.data.database.migration.Migration0064AddCorrectnessToAnswersModel;
import com.quizlet.db.data.database.migration.Migration0065PopulateAnswerCorrectnessColumn;
import com.quizlet.db.data.database.migration.Migration0066AddImageRefTable;
import com.quizlet.db.data.database.migration.Migration0067AddDiagramShapeTable;
import com.quizlet.db.data.database.migration.Migration0068AddIsVerifiedColumnToUser;
import com.quizlet.db.data.database.migration.Migration0069AddAccessCodePrefixColumnToSet;
import com.quizlet.db.data.database.migration.Migration0071AddHasDiagramColumnToStudySet;
import com.quizlet.db.data.database.migration.Migration0072AddQuestionAttributeTable;
import com.quizlet.db.data.database.migration.Migration0073AddPasswordColumnToStudySet;
import com.quizlet.db.data.database.migration.Migration0074AddThumbnailUrlColumnToStudySet;
import com.quizlet.db.data.database.migration.Migration0076AddCreatorIdToDBGroupTable;
import com.quizlet.db.data.database.migration.Migration0077AddAutoJoinLinkToDBGroupTable;
import com.quizlet.db.data.database.migration.Migration0078AddUserIsUnderAgeForAds;
import com.quizlet.db.data.database.migration.Migration0079AddClientTimestampToAllDBModels;
import com.quizlet.db.data.database.migration.Migration0080SetClientTimestampForAllDBModels;
import com.quizlet.db.data.database.migration.Migration0081AddClientTimestampFieldForStudySettingIfMissing;
import com.quizlet.db.data.database.migration.Migration0082SetClientTimestampForStudySettingIfMissing;
import com.quizlet.db.data.database.migration.Migration0083CreateOfflineEntityTable;
import com.quizlet.db.data.database.migration.Migration0085DropOfflineEntityTable;
import com.quizlet.db.data.database.migration.Migration0086RecreateOfflineEntityTable;
import com.quizlet.db.data.database.migration.Migration0087AddColumnIsEligibleForFreeTrialToUserTable;
import com.quizlet.db.data.database.migration.Migration0088AddLargeUrlColumnToImageTable;
import com.quizlet.db.data.database.migration.Migration0089AddRichTextColumnsToTermTable;
import com.quizlet.db.data.database.migration.Migration0090AddMCQAttributeOnDBStudySet;
import com.quizlet.db.data.database.migration.Migration0091AddGroupFolderTable;
import com.quizlet.db.data.database.migration.Migration0092AddFolderIdColumnToGroupSetTable;
import com.quizlet.db.data.database.migration.Migration0093AddDefinitionCustomDistractorsToTermsTable;
import com.quizlet.db.data.database.migration.Migration0094CreateProgressResetTable;
import com.quizlet.db.data.database.migration.Migration0095AddHasOptedIntoFreeOfflinePromoToUserTable;
import com.quizlet.db.data.database.migration.Migration0096AddObfuscatedUserIdToUserTable;
import com.quizlet.db.data.database.migration.Migration0100AddIsSelfLearnerToUserTable;
import com.quizlet.db.data.database.migration.Migration0101AddSignupCountryCodeToUserTable;
import com.quizlet.db.data.database.migration.Migration0102AddIsConfirmationRequiredToUserTable;
import com.quizlet.db.data.database.migration.Migration0103SetIsConfirmationRequiredDefaultValue;
import com.quizlet.db.data.database.migration.Migration0104FixMissingDefaultValues01;
import com.quizlet.db.data.database.migration.Migration0105AddAddNumSetsToGroupTable;
import com.quizlet.db.data.database.migration.Migration0106AddAddNumMembersToGroupTable;
import com.quizlet.db.data.database.migration.Migration0107DropNotifiableDevicesTable;
import com.quizlet.db.data.database.migration.Migration0108AddIsCoursePoweredToFolderTable;
import com.quizlet.db.data.database.migration.Migration0109AddSchoolAndCourseInfoToFolderTable;
import com.quizlet.db.data.database.migration.Migration0110AddCountryCodeToUserTable;
import com.quizlet.db.data.database.migration.Migration0111AddNumSetsToFolderTable;
import com.quizlet.db.data.database.migration.Migration0112DropFolderSetTable;
import com.quizlet.db.data.database.migration.Migration0113DropFeedbackTable;
import com.quizlet.db.data.database.migration.Migration0114AddQPFGenerationMethodToFolderTable;
import com.quizlet.db.data.models.legacy.LegacyFavoriteSet;
import com.quizlet.db.data.models.legacy.LegacyFeedItem;
import com.quizlet.db.data.models.legacy.LegacyFeedResponseWrapper;
import com.quizlet.db.data.models.legacy.LegacyGroupMembership;
import com.quizlet.db.data.models.legacy.LegacyGroupWrapper;
import com.quizlet.db.data.models.legacy.LegacySession;
import com.quizlet.db.data.models.legacy.LegacyUser;
import com.quizlet.db.data.models.persisted.DBAnswer;
import com.quizlet.db.data.models.persisted.DBBookmark;
import com.quizlet.db.data.models.persisted.DBEnteredSetPassword;
import com.quizlet.db.data.models.persisted.DBFolder;
import com.quizlet.db.data.models.persisted.DBGroup;
import com.quizlet.db.data.models.persisted.DBGroupMembership;
import com.quizlet.db.data.models.persisted.DBGroupSet;
import com.quizlet.db.data.models.persisted.DBSchool;
import com.quizlet.db.data.models.persisted.DBSelectedTerm;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBStudySetting;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.DBUser;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import timber.log.c;

/* loaded from: classes2.dex */
public class DatabaseMigrator {
    private static final Class[] mModelClasses = {DBStudySet.class, DBTerm.class, DBUser.class, DBGroup.class, DBGroupMembership.class, DBSchool.class, DBGroupSet.class, DBSession.class, DBStudySetting.class, DBAnswer.class, DBFolder.class, DBBookmark.class, DBSelectedTerm.class, DBEnteredSetPassword.class};
    private final DatabaseHelper mDatabaseHelper;
    private final Long mUserId;

    public DatabaseMigrator(DatabaseHelper databaseHelper, Long l) {
        this.mDatabaseHelper = databaseHelper;
        this.mUserId = l;
    }

    public final ArrayList a(SQLiteDatabase sQLiteDatabase, ConnectionSource connectionSource, int i, int i2) throws SQLException {
        String str;
        Class<LegacyFeedItem> cls;
        Class<LegacyFeedResponseWrapper> cls2;
        int i3;
        Class<DBAnswer> cls3;
        String str2;
        String str3;
        Class<DBFolder> cls4;
        Object obj;
        Object obj2;
        String str4;
        String str5;
        String str6;
        Class cls5;
        Object obj3;
        Dao dao;
        Iterator<String[]> it2;
        Class cls6;
        int i4;
        Object obj4;
        String str7;
        Object[] objArr = {Integer.valueOf(i), Integer.valueOf(i2)};
        timber.log.a aVar = c.a;
        aVar.a("Migrating database from version %d to version %d", objArr);
        ArrayList arrayList = new ArrayList();
        arrayList.add("set");
        arrayList.add("term");
        arrayList.add("user");
        arrayList.add(DBGroup.TABLE_NAME);
        String str8 = DBGroupMembership.TABLE_NAME;
        arrayList.add(DBGroupMembership.TABLE_NAME);
        arrayList.add("school");
        arrayList.add(DBGroupSet.TABLE_NAME);
        String str9 = "local_session";
        arrayList.add("local_session");
        arrayList.add("local_answer");
        aVar.g("DatabaseMigrator onUpgrade", new Object[0]);
        Class<LegacyFeedItem> cls7 = LegacyFeedItem.class;
        Class<LegacyFeedResponseWrapper> cls8 = LegacyFeedResponseWrapper.class;
        Class<LegacyFavoriteSet> cls9 = LegacyFavoriteSet.class;
        if (i < 37) {
            for (int length = mModelClasses.length - 1; length >= 0; length--) {
                TableUtils.dropTable(connectionSource, mModelClasses[length], true);
            }
            TableUtils.dropTable(connectionSource, (Class) cls9, true);
            TableUtils.dropTable(connectionSource, (Class) cls8, true);
            TableUtils.dropTable(connectionSource, (Class) cls7, true);
            TableUtils.dropTable(connectionSource, LegacySession.class, true);
            this.mDatabaseHelper.onCreate(sQLiteDatabase, connectionSource);
            return arrayList;
        }
        String str10 = "ALTER TABLE `";
        Class<DBAnswer> cls10 = DBAnswer.class;
        if (i < 38) {
            int size = arrayList.size() - 1;
            while (size >= 0) {
                this.mDatabaseHelper.getDao(mModelClasses[size]).executeRaw(android.support.v4.media.session.a.t(new StringBuilder("ALTER TABLE `"), (String) arrayList.get(size), "` ADD COLUMN dirty BOOLEAN DEFAULT 1;"), new String[0]);
                size--;
                cls7 = cls7;
                str8 = str8;
                cls8 = cls8;
            }
            str = str8;
            cls = cls7;
            cls2 = cls8;
            i3 = 0;
            this.mDatabaseHelper.getDao(DBSession.class).executeRaw("ALTER TABLE `local_session` ADD COLUMN sessionId LONG DEFAULT -1;", new String[0]);
            this.mDatabaseHelper.getDao(DBSession.class).executeRaw("ALTER TABLE `local_session` ADD COLUMN score LONG DEFAULT -1;", new String[0]);
            this.mDatabaseHelper.getDao(DBSession.class).executeRaw("ALTER TABLE `local_session` ADD COLUMN startedOnServer BOOLEAN DEFAULT 0;", new String[0]);
            this.mDatabaseHelper.getDao(cls10).executeRaw("ALTER TABLE `local_answer` ADD COLUMN sessionId LONG DEFAULT -1;", new String[0]);
        } else {
            str = DBGroupMembership.TABLE_NAME;
            cls = cls7;
            cls2 = cls8;
            i3 = 0;
        }
        if (i < 39) {
            this.mDatabaseHelper.getDao(DBTerm.class).executeRaw("ALTER TABLE `term` ADD COLUMN orderId INT DEFAULT -1;", new String[i3]);
        }
        String str11 = "folder";
        Class<DBFolder> cls11 = DBFolder.class;
        Object obj5 = "local_answer";
        if (i < 40) {
            int size2 = arrayList.size() - 1;
            while (size2 >= 0) {
                Dao dao2 = this.mDatabaseHelper.getDao(mModelClasses[size2]);
                dao2.executeRaw(android.support.v4.media.session.a.t(new StringBuilder("ALTER TABLE `"), (String) arrayList.get(size2), "` ADD COLUMN isDeleted BOOLEAN DEFAULT 0;"), new String[0]);
                dao2.executeRaw(android.support.v4.media.session.a.t(new StringBuilder("ALTER TABLE `"), (String) arrayList.get(size2), "` ADD COLUMN lastModified LONG DEFAULT -1;"), new String[0]);
                size2--;
                str11 = str11;
                str9 = str9;
                cls9 = cls9;
            }
            String str12 = str11;
            str3 = str9;
            Class<LegacyFavoriteSet> cls12 = cls9;
            this.mDatabaseHelper.getDao(DBUser.class).executeRaw("ALTER TABLE `user` ADD COLUMN id INT DEFAULT 0;", new String[0]);
            this.mDatabaseHelper.getDao(DBUser.class).executeRaw("ALTER TABLE `user` ADD COLUMN isTeacher BOOLEAN DEFAULT 0;", new String[0]);
            this.mDatabaseHelper.getDao(DBUser.class).executeRaw("ALTER TABLE `user` ADD COLUMN locked BOOLEAN DEFAULT 0;", new String[0]);
            this.mDatabaseHelper.getDao(DBUser.class).executeRaw("ALTER TABLE `user` ADD COLUMN language VARCHAR;", new String[0]);
            this.mDatabaseHelper.getDao(DBStudySet.class).executeRaw("ALTER TABLE `set` ADD COLUMN termsPreloaded BOOLEAN", new String[0]);
            Dao dao3 = this.mDatabaseHelper.getDao(DBSession.class);
            Dao dao4 = this.mDatabaseHelper.getDao(cls10);
            dao3.executeRaw("ALTER TABLE `local_session` ADD COLUMN id LONG", new String[0]);
            dao3.executeRaw("CREATE UNIQUE INDEX local_session_id ON local_session(id)", new String[0]);
            dao4.executeRaw("ALTER TABLE `local_answer` ADD COLUMN id LONG", new String[0]);
            dao4.executeRaw("CREATE UNIQUE INDEX local_answer_id ON local_answer(id)", new String[0]);
            String[] strArr = new String[2];
            Iterator<String[]> it3 = dao3.queryRaw("SELECT localId, sessionId FROM local_session", new String[0]).getResults().iterator();
            int i5 = -1;
            while (it3.hasNext()) {
                String[] next = it3.next();
                String strF = Long.valueOf(next[1]).longValue() > 0 ? next[1] : android.support.v4.media.session.a.f(i5, "");
                strArr[0] = strF;
                strArr[1] = next[0];
                Iterator<String[]> it4 = it3;
                Dao dao5 = dao3;
                Object[] objArr2 = {strArr[0], strArr[1], Integer.valueOf(dao3.executeRaw("UPDATE local_session SET id=? WHERE localId=?", strArr))};
                timber.log.a aVar2 = c.a;
                aVar2.a("UPDATE local_session SET id=? WHERE localId=?%s_%s_%d", objArr2);
                strArr[0] = strF;
                strArr[1] = next[0];
                aVar2.a("UPDATE local_answer SET sessionId=? WHERE localSessionId=?%s_%s_%d", strArr[0], strArr[1], Integer.valueOf(dao4.executeRaw("UPDATE local_answer SET sessionId=? WHERE localSessionId=?", strArr)));
                i5--;
                cls10 = cls10;
                it3 = it4;
                dao3 = dao5;
            }
            cls3 = cls10;
            char c = 0;
            Iterator<String[]> it5 = dao4.queryRaw("SELECT localId, localSessionId FROM local_answer", new String[0]).getResults().iterator();
            int i6 = -1;
            while (it5.hasNext()) {
                String[] next2 = it5.next();
                strArr[c] = android.support.v4.media.session.a.f(i6, "");
                strArr[1] = next2[c];
                c.a.a("UPDATE local_answer SET id=? WHERE localId=?%s_%s_%d", strArr[c], strArr[1], Integer.valueOf(dao4.executeRaw("UPDATE local_answer SET id=? WHERE localId=?", strArr)));
                i6--;
                it5 = it5;
                c = 0;
            }
            TableUtils.createTable(connectionSource, LegacyGroupWrapper.class);
            TableUtils.createTable(connectionSource, cls11);
            TableUtils.createTable(connectionSource, DBBookmark.class);
            TableUtils.dropTable(connectionSource, (Class) cls12, true);
            str2 = str12;
        } else {
            cls3 = cls10;
            str2 = "folder";
            str3 = "local_session";
            arrayList.add(str2);
            arrayList.add(DBBookmark.TABLE_NAME);
        }
        if (i < 41) {
            c.a.a("UPDATE local_session SET endTimestamp=-1 WHERE endTimestamp IS NULL %d", Integer.valueOf(this.mDatabaseHelper.getDao(DBSession.class).executeRaw("UPDATE local_session SET endTimestamp=-1 WHERE endTimestamp IS NULL", new String[0])));
        }
        String str13 = "UPDATE `";
        if (i < 42) {
            int size3 = arrayList.size() - 1;
            while (size3 >= 0) {
                Dao dao6 = this.mDatabaseHelper.getDao(mModelClasses[size3]);
                String str14 = str10;
                Class<DBFolder> cls13 = cls11;
                dao6.executeRaw(android.support.v4.media.session.a.t(new StringBuilder(str10), (String) arrayList.get(size3), "` ADD COLUMN localGeneratedId INTEGER DEFAULT 0;"), new String[0]);
                String str15 = str3;
                if (((String) arrayList.get(size3)).equals(str15)) {
                    i4 = size3;
                    obj4 = obj5;
                } else {
                    obj4 = obj5;
                    if (((String) arrayList.get(size3)).equals(obj4)) {
                        i4 = size3;
                    } else {
                        i4 = size3;
                        str7 = str13;
                        dao6.executeRaw(android.support.v4.media.session.a.t(new StringBuilder(str13), (String) arrayList.get(size3), "` SET dirty = 0;"), new String[0]);
                        size3 = i4 - 1;
                        str3 = str15;
                        str13 = str7;
                        cls11 = cls13;
                        obj5 = obj4;
                        str10 = str14;
                    }
                }
                str7 = str13;
                size3 = i4 - 1;
                str3 = str15;
                str13 = str7;
                cls11 = cls13;
                obj5 = obj4;
                str10 = str14;
            }
            cls4 = cls11;
            obj2 = obj5;
            str4 = str3;
            str5 = str13;
            this.mDatabaseHelper.getDao(DBStudySet.class).executeRaw("ALTER TABLE `set` ADD COLUMN publishedTimestamp INTEGER;", new String[0]);
            this.mDatabaseHelper.getDao(DBStudySet.class).executeRaw("UPDATE `set` SET publishedTimestamp = createdDate;", new String[0]);
            this.mDatabaseHelper.getDao(DBStudySet.class).executeRaw("ALTER TABLE `set` ADD COLUMN creatorId LONG;", new String[0]);
            this.mDatabaseHelper.getDao(DBStudySet.class).executeRaw("ALTER TABLE `set` ADD COLUMN accessType INTEGER;", new String[0]);
            this.mDatabaseHelper.getDao(DBStudySet.class).executeRaw("ALTER TABLE `set` ADD COLUMN passwordUse BOOLEAN;", new String[0]);
            this.mDatabaseHelper.getDao(DBStudySet.class).executeRaw("ALTER TABLE `set` ADD COLUMN passwordEdit BOOLEAN;", new String[0]);
            this.mDatabaseHelper.getDao(DBStudySet.class).executeRaw("ALTER TABLE `set` ADD COLUMN canEdit BOOLEAN;", new String[0]);
            this.mDatabaseHelper.getDao(DBStudySet.class).executeRaw("ALTER TABLE `set` ADD COLUMN readyToCreate BOOLEAN;", new String[0]);
            obj = DBTerm.class;
            this.mDatabaseHelper.getDao(obj).executeRaw("ALTER TABLE `term` ADD COLUMN largeImageWidth INTEGER;", new String[0]);
            this.mDatabaseHelper.getDao(obj).executeRaw("ALTER TABLE `term` ADD COLUMN largeImageHeight INTEGER;", new String[0]);
            this.mDatabaseHelper.getDao(obj).executeRaw("ALTER TABLE `term` ADD COLUMN largeImageUrl VARCHAR;", new String[0]);
        } else {
            cls4 = cls11;
            obj = DBTerm.class;
            obj2 = obj5;
            str4 = str3;
            str5 = "UPDATE `";
        }
        if (i < 43) {
            this.mDatabaseHelper.getDao(DBStudySet.class).executeRaw("DELETE FROM `set` WHERE id <= 0 AND localGeneratedId = 0;", new String[0]);
        }
        if (i < 44) {
            this.mDatabaseHelper.getDao(DBSession.class).executeRaw("ALTER TABLE `local_session` ADD COLUMN personId INTEGER;", new String[0]);
            this.mDatabaseHelper.getDao(DBSession.class).executeRaw("ALTER TABLE `local_session` ADD COLUMN selectedOnly BOOLEAN DEFAULT 0;", new String[0]);
            TableUtils.createTable(connectionSource, DBSelectedTerm.class);
        } else {
            arrayList.add(DBSelectedTerm.TABLE_NAME);
        }
        if (i < 45) {
            cls5 = LegacySession.class;
            str6 = str2;
            this.mDatabaseHelper.getDao(cls5).executeRaw("ALTER TABLE `session` ADD COLUMN imageUrl VARCHAR;", new String[0]);
        } else {
            str6 = str2;
            cls5 = LegacySession.class;
        }
        if (i < 46) {
            Dao dao7 = this.mDatabaseHelper.getDao(LegacyUser.class);
            obj3 = obj2;
            Iterator<String[]> it6 = dao7.queryRaw("SELECT id, count(username) AS username_count from user GROUP BY id HAVING username_count > 1;", new String[0]).getResults().iterator();
            while (it6.hasNext()) {
                String[] next3 = it6.next();
                long jLongValue = Long.valueOf(next3[1]).longValue();
                if (jLongValue > 1) {
                    String str16 = next3[0];
                    it2 = it6;
                    cls6 = cls5;
                    String[] strArr2 = {str16, str16, android.support.v4.media.session.a.g(jLongValue - 1, "", new StringBuilder())};
                    dao = dao7;
                    c.a.a("%s%s_%s_%s_%d", "DELETE FROM `user` WHERE id=? AND username IN (SELECT username FROM user WHERE id=? LIMIT ?);", strArr2[0], strArr2[1], strArr2[2], Integer.valueOf(dao7.executeRaw("DELETE FROM `user` WHERE id=? AND username IN (SELECT username FROM user WHERE id=? LIMIT ?);", strArr2)));
                } else {
                    dao = dao7;
                    it2 = it6;
                    cls6 = cls5;
                }
                cls5 = cls6;
                it6 = it2;
                dao7 = dao;
            }
            Class cls14 = cls5;
            this.mDatabaseHelper.getDao(DBUser.class).executeRaw("ALTER TABLE `user` RENAME TO legacy_user;", new String[0]);
            TableUtils.createTable(connectionSource, DBUser.class);
            arrayList.remove("user");
            this.mDatabaseHelper.getDao(DBUser.class).updateRaw("INSERT INTO `user` (id, username, timestamp, _imageUrl) SELECT id, username, signUpDate, profileImage FROM legacy_user;", new String[0]);
            TableUtils.dropTable(connectionSource, LegacyUser.class, true);
            this.mDatabaseHelper.getDao(DBGroupMembership.class).executeRaw("ALTER TABLE `group_membership` RENAME TO legacy_group_membership;", new String[0]);
            TableUtils.createTable(connectionSource, DBGroupMembership.class);
            arrayList.remove(str);
            this.mDatabaseHelper.getDao(DBGroupMembership.class).updateRaw("INSERT INTO `group_membership` (id, classId, receiveEmail) SELECT membershipId, groupId, emailNotification FROM legacy_group_membership;", new String[0]);
            TableUtils.dropTable(connectionSource, LegacyGroupMembership.class, true);
            TableUtils.dropTable(connectionSource, LegacyGroupWrapper.class, true);
            TableUtils.dropTable(connectionSource, (Class) cls2, true);
            TableUtils.dropTable(connectionSource, (Class) cls, true);
            this.mDatabaseHelper.getDao(DBGroupSet.class).executeRaw("ALTER TABLE `group_set` ADD COLUMN userId LONG;", new String[0]);
            this.mDatabaseHelper.getDao(DBGroupSet.class).executeRaw("ALTER TABLE `group_set` ADD COLUMN canEdit BOOLEAN DEFAULT 0;", new String[0]);
            this.mDatabaseHelper.getDao(DBGroupSet.class).executeRaw("ALTER TABLE `group_set` ADD COLUMN timestamp INTEGER;", new String[0]);
            TableUtils.createTable(connectionSource, DBEnteredSetPassword.class);
            this.mDatabaseHelper.getDao(DBSession.class).executeRaw("ALTER TABLE `local_session` ADD COLUMN hidden BOOLEAN DEFAULT 0;", new String[0]);
            Class<DBAnswer> cls15 = cls3;
            this.mDatabaseHelper.getDao(cls15).executeRaw("ALTER TABLE `local_answer` ADD COLUMN personId INTEGER DEFAULT " + this.mUserId + ";", new String[0]);
            this.mDatabaseHelper.getDao(cls15).executeRaw("ALTER TABLE `local_answer` ADD COLUMN promptSide INTEGER;", new String[0]);
            this.mDatabaseHelper.getDao(cls14).executeRaw("ALTER TABLE `session` RENAME TO legacy_session;", new String[0]);
            TableUtils.dropTable(connectionSource, cls14, true);
            this.mDatabaseHelper.getDao(DBSession.class).executeRaw("ALTER TABLE `local_session` RENAME TO session;", new String[0]);
            this.mDatabaseHelper.getDao(cls15).executeRaw("ALTER TABLE `local_answer` RENAME TO answer;", new String[0]);
            this.mDatabaseHelper.getDao(DBStudySet.class).executeRaw("ALTER TABLE `set` ADD COLUMN _webUrl VARCHAR;", new String[0]);
            this.mDatabaseHelper.getDao(DBStudySet.class).executeRaw("ALTER TABLE `set` ADD COLUMN parentId LONG;", new String[0]);
            this.mDatabaseHelper.getDao(DBStudySet.class).executeRaw("ALTER TABLE `set` ADD COLUMN creationSource INTEGER;", new String[0]);
            this.mDatabaseHelper.getDao(DBStudySet.class).executeRaw("ALTER TABLE `set` ADD COLUMN privacyLockStatus INTEGER;", new String[0]);
            this.mDatabaseHelper.getDao(obj).executeRaw("ALTER TABLE `term` ADD COLUMN _wordTtsUrl VARCHAR;", new String[0]);
            this.mDatabaseHelper.getDao(obj).executeRaw("ALTER TABLE `term` ADD COLUMN _definitionTtsUrl VARCHAR;", new String[0]);
            this.mDatabaseHelper.getDao(obj).executeRaw("ALTER TABLE `term` ADD COLUMN wordCustomAudioId LONG;", new String[0]);
            this.mDatabaseHelper.getDao(obj).executeRaw("ALTER TABLE `term` ADD COLUMN definitionCustomAudioId LONG;", new String[0]);
            this.mDatabaseHelper.getDao(obj).executeRaw("ALTER TABLE `term` ADD COLUMN definitionImageId LONG;", new String[0]);
        } else {
            obj3 = obj2;
            arrayList.add(DBEnteredSetPassword.TABLE_NAME);
        }
        arrayList.remove(str4);
        arrayList.add("session");
        arrayList.remove(obj3);
        arrayList.add("answer");
        if (i < 48) {
            if (arrayList.contains(str6)) {
                this.mDatabaseHelper.getDao(cls4).executeRaw("ALTER TABLE `folder` ADD COLUMN _webUrl VARCHAR;", new String[0]);
            }
            int iUpdateRaw = 0;
            for (int i7 = 0; i7 < arrayList.size(); i7++) {
                iUpdateRaw += this.mDatabaseHelper.getDao(mModelClasses[i7]).updateRaw(android.support.v4.media.session.a.t(new StringBuilder(str5), (String) arrayList.get(i7), "` SET localGeneratedId = 0 WHERE id > 0 AND localGeneratedId != 0;"), new String[0]);
            }
            c.a.a("Migrated %d records to 0 localId", Integer.valueOf(iUpdateRaw));
        }
        return arrayList;
    }

    public final void b(SQLiteDatabase sQLiteDatabase, ConnectionSource connectionSource, int i, int i2) {
        try {
            LinkedHashSet linkedHashSet = new LinkedHashSet(a(sQLiteDatabase, connectionSource, i, i2));
            DatabaseHelper databaseHelper = this.mDatabaseHelper;
            Migration0049AddStudySettingTable migration0049AddStudySettingTable = new Migration0049AddStudySettingTable(49, 0);
            Migration0050AddSessionItemIdAndItemType migration0050AddSessionItemIdAndItemType = new Migration0050AddSessionItemIdAndItemType(50);
            migration0050AddSessionItemIdAndItemType.b = databaseHelper;
            new com.quizlet.data.repository.course.membership.c((OrmLiteSqliteOpenHelper) databaseHelper, linkedHashSet, migration0049AddStudySettingTable, migration0050AddSessionItemIdAndItemType, new Migration0051AssignPersonIdToAnswers(this.mUserId.longValue()), new Migration0052AddLocaleColumnsToUser(52), new Migration0053AddLocaleColumnsToUser(53), new Migration0054AddUserSettingsColumnsToUser(54), new Migration0055AddCanChangeUsernameToUser(55), new Migration0056ProfileImageIdToUser(56), new Migration0057AddGroupLongTimestamp(57), new Migration0058CopyGroupTimestampToLongField(58), new Migration0059AddUserIsUnderAge(59), new Migration0060AddImageTable(60, 0), new Migration0061AddUserNeedsChildDirectedTreatment(61), new Migration0062AddNotificationColumnsToUser(62), new Migration0063AddUserStudyableTable(63, 0), new Migration0064AddCorrectnessToAnswersModel(64), new Migration0065PopulateAnswerCorrectnessColumn(65), new Migration0066AddImageRefTable(66, 0), new Migration0067AddDiagramShapeTable(67, 0), new Migration0068AddIsVerifiedColumnToUser(68), new Migration0069AddAccessCodePrefixColumnToSet(69), new Migration0071AddHasDiagramColumnToStudySet(71), new Migration0072AddQuestionAttributeTable(), new Migration0073AddPasswordColumnToStudySet(73), new Migration0074AddThumbnailUrlColumnToStudySet(74), new Migration0076AddCreatorIdToDBGroupTable(76), new Migration0077AddAutoJoinLinkToDBGroupTable(77), new Migration0078AddUserIsUnderAgeForAds(78), new Migration0079AddClientTimestampToAllDBModels(79), new Migration0080SetClientTimestampForAllDBModels(80), new Migration0081AddClientTimestampFieldForStudySettingIfMissing(81), new Migration0082SetClientTimestampForStudySettingIfMissing(82), new Migration0083CreateOfflineEntityTable(83, 0), new Migration0085DropOfflineEntityTable(85, 1), new Migration0086RecreateOfflineEntityTable(86, 0), new Migration0087AddColumnIsEligibleForFreeTrialToUserTable(87), new Migration0088AddLargeUrlColumnToImageTable(88), new Migration0089AddRichTextColumnsToTermTable(89), new Migration0090AddMCQAttributeOnDBStudySet(90), new Migration0091AddGroupFolderTable(91, 0), new Migration0092AddFolderIdColumnToGroupSetTable(92), new Migration0093AddDefinitionCustomDistractorsToTermsTable(93), new Migration0094CreateProgressResetTable(94, 0), new Migration0095AddHasOptedIntoFreeOfflinePromoToUserTable(95), new Migration0096AddObfuscatedUserIdToUserTable(96), new Migration0100AddIsSelfLearnerToUserTable(100), new Migration0101AddSignupCountryCodeToUserTable(101), new Migration0102AddIsConfirmationRequiredToUserTable(102), new Migration0103SetIsConfirmationRequiredDefaultValue(103), new Migration0104FixMissingDefaultValues01(104), new Migration0105AddAddNumSetsToGroupTable(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_CONSENT_EXPIRED), new Migration0106AddAddNumMembersToGroupTable(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SERVICE_SPECIFIC_OFF), new Migration0107DropNotifiableDevicesTable(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED, 1), new Migration0108AddIsCoursePoweredToFolderTable(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY), new Migration0109AddSchoolAndCourseInfoToFolderTable(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_MOVED_REGION), new Migration0110AddCountryCodeToUserTable(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SHOW_BANNER_CALLED), new Migration0111AddNumSetsToFolderTable(111), new Migration0112DropFolderSetTable(ContentType.LONG_FORM_ON_DEMAND, 1), new Migration0113DropFeedbackTable(ContentType.LIVE, 1), new Migration0114AddQPFGenerationMethodToFolderTable(114)).m(sQLiteDatabase, connectionSource, i, i2);
        } catch (SQLException e) {
            c.a.f(e, "Error modifying database", new Object[0]);
            throw new RuntimeException(e);
        }
    }
}
