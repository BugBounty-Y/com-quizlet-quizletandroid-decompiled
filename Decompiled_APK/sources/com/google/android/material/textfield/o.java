package com.google.android.material.textfield;

import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.EditText;
import com.quizlet.features.match.data.C4345a;
import com.quizlet.quizletandroid.ui.studymodes.match.view.MatchCardView;
import com.quizlet.studiablemodels.StudiableAudio;
import com.quizlet.studiablemodels.StudiableText;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class o extends View.AccessibilityDelegate {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ o(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.view.View.AccessibilityDelegate
    public void onInitializeAccessibilityNodeInfo(View view, AccessibilityNodeInfo accessibilityNodeInfo) {
        switch (this.a) {
            case 0:
                super.onInitializeAccessibilityNodeInfo(view, accessibilityNodeInfo);
                EditText editText = ((p) this.b).h.getEditText();
                if (editText != null) {
                    accessibilityNodeInfo.setLabeledBy(editText);
                    break;
                }
                break;
            default:
                super.onInitializeAccessibilityNodeInfo(view, accessibilityNodeInfo);
                break;
        }
    }

    @Override // android.view.View.AccessibilityDelegate
    public boolean onRequestSendAccessibilityEvent(ViewGroup host, View child, AccessibilityEvent event) {
        switch (this.a) {
            case 1:
                Intrinsics.checkNotNullParameter(host, "host");
                Intrinsics.checkNotNullParameter(child, "child");
                Intrinsics.checkNotNullParameter(event, "event");
                int eventType = event.getEventType();
                MatchCardView matchCardView = (MatchCardView) this.b;
                C4345a c4345a = matchCardView.f;
                if (c4345a == null || eventType != 32768) {
                    return true;
                }
                StudiableAudio studiableAudio = c4345a.e;
                String str = studiableAudio != null ? studiableAudio.a : null;
                if (str != null) {
                    com.quizlet.quizletandroid.managers.audio.h hVar = matchCardView.b;
                    if (hVar == null) {
                        Intrinsics.m("audioManager");
                        throw null;
                    }
                    hVar.a(str).f(new com.quizlet.background.eventlogging.a(2), new com.quizlet.billing.manager.d(timber.log.c.a, 17));
                } else {
                    StudiableText studiableText = c4345a.c;
                    com.quizlet.quizletandroid.managers.audio.c cVar = new com.quizlet.quizletandroid.managers.audio.c(-1, 0L, studiableText != null ? studiableText.a : null, studiableText != null ? studiableText.b : null);
                    io.ktor.client.plugins.api.d dVar = matchCardView.c;
                    if (dVar == null) {
                        Intrinsics.m("audioPlayFailureManager");
                        throw null;
                    }
                    dVar.A(cVar);
                }
                return false;
            default:
                return super.onRequestSendAccessibilityEvent(host, child, event);
        }
    }
}
