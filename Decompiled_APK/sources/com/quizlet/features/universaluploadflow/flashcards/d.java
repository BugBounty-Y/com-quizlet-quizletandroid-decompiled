package com.quizlet.features.universaluploadflow.flashcards;

import androidx.compose.animation.C0292t;
import androidx.compose.animation.E;
import androidx.compose.animation.V;
import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.foundation.lazy.o;
import androidx.datastore.core.CorruptionException;
import androidx.navigation.Y;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.Q6;
import com.quizlet.db.data.models.persisted.DBFolder;
import com.quizlet.eventlogger.model.LibraryEventLog;
import com.quizlet.features.flashcards.C4237k;
import com.quizlet.generated.enums.W;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class d implements Function1 {
    public final /* synthetic */ int a;

    public /* synthetic */ d(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) throws CorruptionException {
        switch (this.a) {
            case 0:
                androidx.compose.foundation.lazy.g LazyColumn = (androidx.compose.foundation.lazy.g) obj;
                Intrinsics.checkNotNullParameter(LazyColumn, "$this$LazyColumn");
                LazyColumn.q(4, null, o.c, c.b);
                return Unit.a;
            case 1:
                Intrinsics.checkNotNullParameter((com.quizlet.features.universaluploadflow.flashcards.data.h) obj, "it");
                return Unit.a;
            case 2:
                Y popUpTo = (Y) obj;
                Intrinsics.checkNotNullParameter(popUpTo, "$this$popUpTo");
                popUpTo.a = true;
                return Unit.a;
            case 3:
                Y popUpTo2 = (Y) obj;
                Intrinsics.checkNotNullParameter(popUpTo2, "$this$popUpTo");
                popUpTo2.a = true;
                return Unit.a;
            case 4:
                return Boolean.valueOf(((DBFolder) obj).getIsHidden());
            case 5:
                ((Long) obj).longValue();
                return Unit.a;
            case 6:
                Throwable it2 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                timber.log.c.a.e(it2);
                return Unit.a;
            case 7:
                C0292t AnimatedContent = (C0292t) obj;
                Intrinsics.checkNotNullParameter(AnimatedContent, "$this$AnimatedContent");
                com.quizlet.themes.a aVar = com.quizlet.themes.a.c;
                return E.l(V.g(AbstractC0240f.r(150, 0, aVar.b(), 2), new C4237k(6)), V.i(AbstractC0240f.r(150, 0, aVar.c(), 2), new d(8)));
            case 8:
                return Integer.valueOf(-((Integer) obj).intValue());
            case 9:
                androidx.compose.ui.graphics.drawscope.d LinearProgressIndicator = (androidx.compose.ui.graphics.drawscope.d) obj;
                Intrinsics.checkNotNullParameter(LinearProgressIndicator, "$this$LinearProgressIndicator");
                return Unit.a;
            case 10:
                LibraryEventLog.Payload createEvent = (LibraryEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setClickCategory(W.BROWSE.a());
                return Unit.a;
            case 11:
                LibraryEventLog.Payload createEvent2 = (LibraryEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent2, "$this$createEvent");
                createEvent2.setLocation("Library");
                return Unit.a;
            case 12:
                LibraryEventLog.Payload createEvent3 = (LibraryEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent3, "$this$createEvent");
                createEvent3.setClickCategory(W.BROWSE.a());
                return Unit.a;
            case 13:
                LibraryEventLog.Payload createEvent4 = (LibraryEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent4, "$this$createEvent");
                createEvent4.setClickCategory(W.BROWSE.a());
                return Unit.a;
            case 14:
                LibraryEventLog.Payload createEvent5 = (LibraryEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent5, "$this$createEvent");
                createEvent5.setClickCategory(W.BROWSE.a());
                return Unit.a;
            case 15:
                LibraryEventLog.Payload createEvent6 = (LibraryEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent6, "$this$createEvent");
                createEvent6.setLocation("Library");
                return Unit.a;
            case 16:
                LibraryEventLog.Payload createEvent7 = (LibraryEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent7, "$this$createEvent");
                createEvent7.setLocation("Library");
                return Unit.a;
            case 17:
                LibraryEventLog.Payload createEvent8 = (LibraryEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent8, "$this$createEvent");
                createEvent8.setClickCategory(W.BROWSE.a());
                return Unit.a;
            case 18:
                LibraryEventLog.Payload createEvent9 = (LibraryEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent9, "$this$createEvent");
                createEvent9.setClickCategory(W.BROWSE.a());
                return Unit.a;
            case 19:
                LibraryEventLog.Payload createEvent10 = (LibraryEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent10, "$this$createEvent");
                createEvent10.setLocation("Library");
                return Unit.a;
            case 20:
                CorruptionException it3 = (CorruptionException) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                timber.log.c.a.f(it3, "GlobalCacheDataStore Corruption handling of " + it3, new Object[0]);
                return Q6.a();
            case 21:
                CorruptionException it4 = (CorruptionException) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                timber.log.c.a.g("flashcardsPreferencesDataStore Corruption handling of " + it4, new Object[0]);
                throw it4;
            case EventType.WINDOW_STATE /* 22 */:
                CorruptionException it5 = (CorruptionException) obj;
                Intrinsics.checkNotNullParameter(it5, "it");
                timber.log.c.a.g("userMeteringInfoDataStore Corruption handling of " + it5, new Object[0]);
                throw it5;
            case EventType.AUDIO /* 23 */:
                CorruptionException it6 = (CorruptionException) obj;
                Intrinsics.checkNotNullParameter(it6, "it");
                timber.log.c.a.f(it6, "confirmationWallDataStore Corruption handling of " + it6, new Object[0]);
                return Q6.a();
            case EventType.VIDEO /* 24 */:
                CorruptionException it7 = (CorruptionException) obj;
                Intrinsics.checkNotNullParameter(it7, "it");
                timber.log.c.a.f(it7, "creatorMarketingPreferencesStore Corruption handling of " + it7, new Object[0]);
                return Q6.a();
            case EventType.SUBS /* 25 */:
                CorruptionException it8 = (CorruptionException) obj;
                Intrinsics.checkNotNullParameter(it8, "it");
                timber.log.c.a.f(it8, "folderPreferencesDataStore Corruption handling of " + it8, new Object[0]);
                return Q6.a();
            case EventType.CDN /* 26 */:
                CorruptionException it9 = (CorruptionException) obj;
                Intrinsics.checkNotNullParameter(it9, "it");
                timber.log.c.a.f(it9, "growthBookEnrollmentDataStore Corruption handling of " + it9, new Object[0]);
                return Q6.a();
            case 27:
                CorruptionException it10 = (CorruptionException) obj;
                Intrinsics.checkNotNullParameter(it10, "it");
                timber.log.c.a.f(it10, "httpCookieDataStore Corruption handling of " + it10, new Object[0]);
                return Q6.a();
            case 28:
                CorruptionException it11 = (CorruptionException) obj;
                Intrinsics.checkNotNullParameter(it11, "it");
                timber.log.c.a.f(it11, "libraryPreferencesDataStore Corruption handling of " + it11, new Object[0]);
                return Q6.a();
            default:
                CorruptionException it12 = (CorruptionException) obj;
                Intrinsics.checkNotNullParameter(it12, "it");
                timber.log.c.a.f(it12, "notesPreferencesDataStore Corruption handling of " + it12, new Object[0]);
                return Q6.a();
        }
    }
}
