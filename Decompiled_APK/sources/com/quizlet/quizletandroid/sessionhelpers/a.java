package com.quizlet.quizletandroid.sessionhelpers;

import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import androidx.camera.camera2.internal.a0;
import androidx.lifecycle.I;
import androidx.lifecycle.InterfaceC1250k;
import androidx.lifecycle.J;
import com.quizlet.api.model.TermContentSuggestions;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.model.EditActionsLog;
import com.quizlet.eventlogger.model.EditSessionsLog;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;
import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements InterfaceC1250k, I {
    public EditSessionLoggingHelperState a;

    public a(String str, Intent intent) {
        String str2 = TextUtils.isEmpty(str) ? "?" : "9.34.3";
        if (intent != null) {
            h(intent.getExtras());
        }
        if (this.a == null) {
            String versionString = android.support.v4.media.session.a.l(str2, ":", str);
            EditSessionsLog.b.getClass();
            Intrinsics.checkNotNullParameter(versionString, "versionString");
            Intrinsics.checkNotNullParameter("create", "action");
            EditSessionsLog sessionEvent = new EditSessionsLog(null, 1, null);
            sessionEvent.getPayload().setEditSessionId(UUID.randomUUID().toString());
            sessionEvent.getPayload().setModelType(1);
            sessionEvent.getPayload().setClientStartTimestamp(Long.valueOf(assistantMode.refactored.a.f() / 1000));
            sessionEvent.getPayload().setVersion(Build.VERSION.RELEASE + ":" + versionString);
            sessionEvent.c();
            Intrinsics.checkNotNullParameter(sessionEvent, "sessionEvent");
            this.a = new EditSessionLoggingHelperState(new HashMap(), new ArrayList(), sessionEvent, null, null, null);
        }
    }

    public static boolean b(String str) {
        return "term".equals(str) || "word".equals(str) || "definition".equals(str) || "image".equals(str);
    }

    public final EditActionsLog a(String actionName, Long l, Long l2) {
        if (l2 == null || l2.longValue() <= 0) {
            l2 = null;
        }
        String str = actionName + "_" + l + "_" + l2;
        EditActionsLog editActionsLog = (EditActionsLog) this.a.a.get(str);
        if (editActionsLog != null) {
            return editActionsLog;
        }
        String editSessionId = this.a.c.getSessionId();
        EditActionsLog.b.getClass();
        Intrinsics.checkNotNullParameter(editSessionId, "editSessionId");
        Intrinsics.checkNotNullParameter(actionName, "actionName");
        if (l2 == null || l2.longValue() <= 0) {
            l2 = null;
        }
        EditActionsLog editActionsLog2 = new EditActionsLog(null, 1, null);
        editActionsLog2.setAction(actionName);
        editActionsLog2.getPayload().setEditSessionId(editSessionId);
        editActionsLog2.getPayload().setClientModelId(l);
        editActionsLog2.getPayload().setServerModelId(l2);
        if (l != null || l2 != null) {
            editActionsLog2.getPayload().setModelType(11);
        }
        this.a.a.put(str, editActionsLog2);
        return editActionsLog2;
    }

    public final void c(int i, int i2, Intent intent) {
        if (intent == null) {
            return;
        }
        if (i == 2000 || i == 1000) {
            h(intent.getExtras());
        }
    }

    public final void e(String str) {
        g();
        a(str, null, null).d();
    }

    public final void f(DBTerm dBTerm, boolean z, Long l, TermContentSuggestions termContentSuggestions) {
        EditActionsLog editActionsLogA = a(z ? "word" : "definition", Long.valueOf(dBTerm.getLocalId()), Long.valueOf(dBTerm.getId()));
        if (termContentSuggestions == null) {
            return;
        }
        editActionsLogA.getPayload().setPredictionRequestUuid(termContentSuggestions.requestId);
        if (l == null) {
            return;
        }
        List<TermContentSuggestions.Suggestions> suggestions = termContentSuggestions.suggestions;
        Intrinsics.checkNotNullExpressionValue(suggestions, "suggestions");
        int i = 0;
        for (Object obj : suggestions) {
            int i2 = i + 1;
            if (i < 0) {
                B.p();
                throw null;
            }
            if (((TermContentSuggestions.Suggestions) obj).id == l.longValue()) {
                editActionsLogA.getPayload().setUsedPrediction(Boolean.TRUE);
                editActionsLogA.getPayload().setPredictionSelectionId(l);
                editActionsLogA.getPayload().setPredictionSelectionDepth(Integer.valueOf(i));
                return;
            }
            i = i2;
        }
    }

    public final void g() {
        EditSessionLoggingHelperState editSessionLoggingHelperState = this.a;
        if (editSessionLoggingHelperState.f == null || editSessionLoggingHelperState.e == null) {
            editSessionLoggingHelperState.f = null;
            editSessionLoggingHelperState.e = null;
            return;
        }
        int iF = ((int) (assistantMode.refactored.a.f() - this.a.e.getTime())) / 1000;
        if (!b(this.a.f.a)) {
            if ("language".equals(this.a.f.a)) {
                EditActionsLog editActionsLogA = a("language", null, null);
                editActionsLogA.c(iF);
                editActionsLogA.d();
                return;
            }
            return;
        }
        SavedAction savedAction = this.a.f;
        Long l = savedAction.b;
        Long l2 = savedAction.d;
        if (l2 == null || l2.longValue() <= 0) {
            l2 = null;
        }
        long j = iF;
        j(a("term", l, l2), j);
        b bVar = this.a.d;
        if (bVar == b.a) {
            j(a("word", l, l2), j);
        } else if (bVar == b.b) {
            j(a("definition", l, l2), j);
        } else if (bVar == b.c) {
            j(a("image", l, l2), j);
            j(a("definition", l, l2), j);
        }
        EditSessionLoggingHelperState editSessionLoggingHelperState2 = this.a;
        editSessionLoggingHelperState2.e = null;
        editSessionLoggingHelperState2.d = null;
    }

    public final void h(Bundle bundle) {
        EditSessionLoggingHelperState editSessionLoggingHelperState;
        if (bundle == null || (editSessionLoggingHelperState = (EditSessionLoggingHelperState) bundle.getParcelable("editSessionTrackerKey")) == null) {
            return;
        }
        this.a = editSessionLoggingHelperState;
    }

    public final void i(String str, Long l, Long l2) {
        g();
        if ("word".equals(str)) {
            this.a.d = b.a;
        } else if ("definition".equals(str)) {
            this.a.d = b.b;
        } else if ("image".equals(str)) {
            this.a.d = b.c;
        }
        this.a.e = new Date();
        this.a.f = new SavedAction(str, l, l2);
    }

    public final void j(EditActionsLog editActionsLog, long j) {
        editActionsLog.c((int) j);
        editActionsLog.d();
        this.a.c.c();
    }

    public final void k(EventLogger eventLogger, String str) {
        g();
        this.a.c.setEndtype(str);
        ArrayList arrayList = new ArrayList();
        Iterator it2 = this.a.b.iterator();
        while (it2.hasNext()) {
            EditActionsLog editActionsLog = (EditActionsLog) it2.next();
            if (editActionsLog != null && (!b(editActionsLog.getAction()) || (editActionsLog.getEditTimeSec() != null && editActionsLog.getEditTimeSec().intValue() > 1))) {
                arrayList.add(editActionsLog);
            }
        }
        for (EditActionsLog editActionsLog2 : this.a.a.values()) {
            if (editActionsLog2 != null && (!b(editActionsLog2.getAction()) || (editActionsLog2.getEditTimeSec() != null && editActionsLog2.getEditTimeSec().intValue() > 1))) {
                arrayList.add(editActionsLog2);
            }
        }
        Collections.sort(arrayList, new a0(21));
        Iterator it3 = arrayList.iterator();
        while (it3.hasNext()) {
            eventLogger.v((EditActionsLog) it3.next());
        }
        eventLogger.v(this.a.c);
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onPause(J j) {
        g();
        this.a.e = new Date();
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onResume(J j) {
        if (this.a.a.size() + this.a.b.size() > 0) {
            EditSessionLoggingHelperState editSessionLoggingHelperState = this.a;
            if (editSessionLoggingHelperState.e != null) {
                String editSessionId = editSessionLoggingHelperState.c.getSessionId();
                EditActionsLog.b.getClass();
                Intrinsics.checkNotNullParameter(editSessionId, "editSessionId");
                Intrinsics.checkNotNullParameter("background", "actionName");
                EditActionsLog editActionsLog = new EditActionsLog(null, 1, null);
                editActionsLog.setAction("background");
                editActionsLog.getPayload().setEditSessionId(editSessionId);
                editActionsLog.c(((int) (new Date().getTime() - this.a.e.getTime())) / 1000);
                this.a.b.add(editActionsLog);
                this.a.e = null;
            }
        }
        SavedAction savedAction = this.a.f;
        if (savedAction != null) {
            String str = savedAction.a;
            Long l = savedAction.d;
            Long l2 = savedAction.b;
            if (l2 != null || l != null) {
                i(str, l2, l);
                return;
            }
            g();
            this.a.f = new SavedAction(str, null, null);
            this.a.e = new Date();
        }
    }
}
