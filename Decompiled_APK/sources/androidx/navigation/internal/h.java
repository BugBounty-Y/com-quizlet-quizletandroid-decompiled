package androidx.navigation.internal;

import com.comscore.streaming.EventType;
import com.quizlet.diagrams.DiagramWebView;
import com.quizlet.eventlogger.features.achievements.AchievementsEventLog;
import com.quizlet.eventlogger.features.achievements.AchievementsToastInteractionEventLog;
import com.quizlet.eventlogger.model.NavigationEventLog;
import com.quizlet.eventlogger.model.NotesEventLog;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class h implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;

    public /* synthetic */ h(String str, int i) {
        this.a = i;
        this.b = str;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                break;
            case 1:
                break;
            case 2:
                break;
            case 3:
                break;
            case 4:
                break;
            case 5:
                break;
            case 6:
                break;
            case 7:
                break;
            case 8:
                break;
            case 9:
                break;
            case 10:
                break;
            case 11:
                break;
            case 12:
                break;
            case 13:
                DiagramWebView webView = (DiagramWebView) obj;
                Intrinsics.checkNotNullParameter(webView, "webView");
                webView.loadDataWithBaseURL("file:///android_asset/", this.b, "text/html", "utf-8", null);
                break;
            case 14:
                AchievementsEventLog.Payload createEvent = (AchievementsEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setBadgeId(this.b);
                break;
            case 15:
                AchievementsToastInteractionEventLog.Payload createEvent2 = (AchievementsToastInteractionEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent2, "$this$createEvent");
                createEvent2.c(null, this.b);
                break;
            case 16:
                AchievementsToastInteractionEventLog.Payload createEvent3 = (AchievementsToastInteractionEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent3, "$this$createEvent");
                createEvent3.c(null, this.b);
                break;
            case 17:
                NavigationEventLog.Payload it2 = (NavigationEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                it2.setTagName(this.b);
                break;
            case 18:
                NavigationEventLog.Payload it3 = (NavigationEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                it3.setTagName(this.b);
                break;
            case 19:
                NavigationEventLog.Payload it4 = (NavigationEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                it4.setTagName(this.b);
                it4.setIsPeerRec(Boolean.FALSE);
                break;
            case 20:
                NavigationEventLog.Payload it5 = (NavigationEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(it5, "it");
                it5.setTagName(this.b);
                it5.setIsPeerRec(Boolean.FALSE);
                break;
            case 21:
                NavigationEventLog.Payload it6 = (NavigationEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(it6, "it");
                it6.setTagName(this.b);
                break;
            case EventType.WINDOW_STATE /* 22 */:
                String url = (String) obj;
                Intrinsics.checkNotNullParameter(url, "url");
                Object[] args = {this.b, url};
                Intrinsics.checkNotNullParameter(args, "args");
                break;
            case EventType.AUDIO /* 23 */:
                NotesEventLog.Payload createEvent4 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent4, "$this$createEvent");
                createEvent4.setNoteUuid(this.b);
                break;
            case EventType.VIDEO /* 24 */:
                NotesEventLog.Payload createEvent5 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent5, "$this$createEvent");
                createEvent5.setNoteUuid(this.b);
                break;
            case EventType.SUBS /* 25 */:
                NotesEventLog.Payload createEvent6 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent6, "$this$createEvent");
                createEvent6.setNoteUuid(this.b);
                break;
            case EventType.CDN /* 26 */:
                NotesEventLog.Payload createEvent7 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent7, "$this$createEvent");
                createEvent7.setNoteUuid(this.b);
                break;
            case 27:
                NotesEventLog.Payload createEvent8 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent8, "$this$createEvent");
                createEvent8.setNoteUuid(this.b);
                break;
            case 28:
                NotesEventLog.Payload createEvent9 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent9, "$this$createEvent");
                createEvent9.setNoteUuid(this.b);
                break;
            default:
                NotesEventLog.Payload createEvent10 = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent10, "$this$createEvent");
                createEvent10.setNoteUuid(this.b);
                break;
        }
        return Unit.a;
    }
}
