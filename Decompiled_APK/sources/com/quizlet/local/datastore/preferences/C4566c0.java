package com.quizlet.local.datastore.preferences;

import android.media.MediaPlayer;
import androidx.datastore.core.CorruptionException;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.Q6;
import com.quizlet.data.model.C4181y;
import com.quizlet.data.model.F1;
import com.quizlet.db.data.models.persisted.DBFolder;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.DBUser;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.local.datastore.preferences.c0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final /* synthetic */ class C4566c0 implements Function1 {
    public final /* synthetic */ int a;

    public /* synthetic */ C4566c0(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) throws IllegalStateException {
        switch (this.a) {
            case 0:
                CorruptionException it2 = (CorruptionException) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                timber.log.c.a.f(it2, "onboardingELLPreferencesStore Corruption handling of " + it2, new Object[0]);
                return Q6.a();
            case 1:
                CorruptionException it3 = (CorruptionException) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                timber.log.c.a.f(it3, "onboardingFlashcardsPreferencesStore Corruption handling of " + it3, new Object[0]);
                return Q6.a();
            case 2:
                CorruptionException it4 = (CorruptionException) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                timber.log.c.a.f(it4, "onboardingQPlusUpsellPreferencesDataStore Corruption handling of " + it4, new Object[0]);
                return Q6.a();
            case 3:
                CorruptionException it5 = (CorruptionException) obj;
                Intrinsics.checkNotNullParameter(it5, "it");
                timber.log.c.a.f(it5, "onboardingSurveyPreferencesStore Corruption handling of " + it5, new Object[0]);
                return Q6.a();
            case 4:
                CorruptionException it6 = (CorruptionException) obj;
                Intrinsics.checkNotNullParameter(it6, "it");
                timber.log.c.a.f(it6, "qIncentivesPreferencesDataStore Corruption handling of " + it6, new Object[0]);
                return Q6.a();
            case 5:
                CorruptionException it7 = (CorruptionException) obj;
                Intrinsics.checkNotNullParameter(it7, "it");
                timber.log.c.a.f(it7, "soundEffectsDataStore Corruption handling of " + it7, new Object[0]);
                return Q6.a();
            case 6:
                CorruptionException it8 = (CorruptionException) obj;
                Intrinsics.checkNotNullParameter(it8, "it");
                timber.log.c.a.f(it8, "termListPreferencesDataStore Corruption handling of " + it8, new Object[0]);
                return Q6.a();
            case 7:
                DBFolder folder = (DBFolder) obj;
                Intrinsics.checkNotNullParameter(folder, "folder");
                long id = folder.getId();
                long localId = folder.getLocalId();
                StringBuilder sbT = androidx.compose.animation.d0.t(id, "\n                UPDATE folder\n                SET id = ", "\n                WHERE localGeneratedId = ");
                sbT.append(localId);
                sbT.append(";\n        ");
                return kotlin.text.x.c(sbT.toString());
            case 8:
                com.quizlet.data.repository.classfolder.a it9 = (com.quizlet.data.repository.classfolder.a) obj;
                Intrinsics.checkNotNullParameter(it9, "it");
                return android.support.v4.media.session.a.g(it9.b, ")", androidx.compose.animation.d0.t(it9.a, "(groupId = ", " AND folderId = "));
            case 9:
                com.quizlet.data.repository.classset.a it10 = (com.quizlet.data.repository.classset.a) obj;
                Intrinsics.checkNotNullParameter(it10, "it");
                return android.support.v4.media.session.a.g(it10.b, ")", androidx.compose.animation.d0.t(it10.a, "(groupId = ", " AND setId = "));
            case 10:
                F1 it11 = (F1) obj;
                Intrinsics.checkNotNullParameter(it11, "it");
                return android.support.v4.media.session.a.g(it11.b, ")", androidx.compose.animation.d0.t(it11.a, "(termId = ", " AND personId = "));
            case 11:
                DBStudySet studySet = (DBStudySet) obj;
                Intrinsics.checkNotNullParameter(studySet, "studySet");
                long id2 = studySet.getId();
                long localId2 = studySet.getLocalId();
                StringBuilder sbT2 = androidx.compose.animation.d0.t(id2, "\n                UPDATE set\n                SET id = ", "\n                WHERE localGeneratedId = ");
                sbT2.append(localId2);
                sbT2.append(";\n        ");
                return kotlin.text.x.c(sbT2.toString());
            case 12:
                DBTerm term = (DBTerm) obj;
                Intrinsics.checkNotNullParameter(term, "term");
                long id3 = term.getId();
                long localId3 = term.getLocalId();
                StringBuilder sbT3 = androidx.compose.animation.d0.t(id3, "\n                UPDATE term\n                SET id = ", "\n                WHERE localGeneratedId = ");
                sbT3.append(localId3);
                sbT3.append(";\n        ");
                return kotlin.text.x.c(sbT3.toString());
            case 13:
                C4181y it12 = (C4181y) obj;
                Intrinsics.checkNotNullParameter(it12, "it");
                return Long.valueOf(it12.c);
            case 14:
                androidx.navigation.L navigate = (androidx.navigation.L) obj;
                Intrinsics.checkNotNullParameter(navigate, "$this$navigate");
                navigate.b = true;
                return Unit.a;
            case 15:
                androidx.navigation.L navigate2 = (androidx.navigation.L) obj;
                Intrinsics.checkNotNullParameter(navigate2, "$this$navigate");
                navigate2.b = true;
                return Unit.a;
            case 16:
                androidx.navigation.L navOptions = (androidx.navigation.L) obj;
                Intrinsics.checkNotNullParameter(navOptions, "$this$navOptions");
                navOptions.b = true;
                return Unit.a;
            case 17:
                androidx.navigation.L navigate3 = (androidx.navigation.L) obj;
                Intrinsics.checkNotNullParameter(navigate3, "$this$navigate");
                navigate3.b = true;
                return Unit.a;
            case 18:
                androidx.navigation.Y popUpTo = (androidx.navigation.Y) obj;
                Intrinsics.checkNotNullParameter(popUpTo, "$this$popUpTo");
                popUpTo.a = true;
                return Unit.a;
            case 19:
                Throwable it13 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(it13, "it");
                timber.log.c.a.q(it13, "Error trying to set up OfflineSnackbar", new Object[0]);
                return Unit.a;
            case 20:
                MediaPlayer mediaPlayer = (MediaPlayer) obj;
                if (mediaPlayer.isPlaying()) {
                    timber.log.c.a.g("Stopped MediaPlayer playback.", new Object[0]);
                    mediaPlayer.stop();
                }
                return Unit.a;
            case 21:
                DBUser u = (DBUser) obj;
                Intrinsics.checkNotNullParameter(u, "u");
                boolean z = true;
                if (u.getUserUpgradeType() != 1 && u.getUserUpgradeType() != 3) {
                    z = false;
                }
                return Boolean.valueOf(z);
            case EventType.WINDOW_STATE /* 22 */:
                DBUser u2 = (DBUser) obj;
                Intrinsics.checkNotNullParameter(u2, "u");
                return Integer.valueOf(u2.getTimestamp());
            case EventType.AUDIO /* 23 */:
                DBUser u3 = (DBUser) obj;
                Intrinsics.checkNotNullParameter(u3, "u");
                String signupCountryCode = u3.getSignupCountryCode();
                return signupCountryCode == null ? "" : signupCountryCode;
            case EventType.VIDEO /* 24 */:
                DBUser u4 = (DBUser) obj;
                Intrinsics.checkNotNullParameter(u4, "u");
                return Boolean.valueOf(u4.getUserUpgradeType() == 2);
            case EventType.SUBS /* 25 */:
                DBUser u5 = (DBUser) obj;
                Intrinsics.checkNotNullParameter(u5, "u");
                return Boolean.valueOf(u5.getIsEligibleForFreeTrial());
            case EventType.CDN /* 26 */:
                DBUser u6 = (DBUser) obj;
                Intrinsics.checkNotNullParameter(u6, "u");
                return Boolean.valueOf(u6.getIsConfirmed());
            case 27:
                DBUser u7 = (DBUser) obj;
                Intrinsics.checkNotNullParameter(u7, "u");
                return Boolean.valueOf(u7.needsChildDirectedTreatment());
            case 28:
                DBUser u8 = (DBUser) obj;
                Intrinsics.checkNotNullParameter(u8, "u");
                return Long.valueOf(u8.getId());
            default:
                DBUser u9 = (DBUser) obj;
                Intrinsics.checkNotNullParameter(u9, "u");
                return Integer.valueOf(u9.getSelfIdentifiedUserType());
        }
    }
}
