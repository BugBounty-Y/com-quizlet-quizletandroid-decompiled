package com.quizlet.quizletandroid.util;

import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityEvent;
import com.quizlet.quizletandroid.R;

/* loaded from: classes3.dex */
public final class b extends View.AccessibilityDelegate {
    public static final /* synthetic */ int c = 0;
    public final /* synthetic */ com.quizlet.quizletandroid.managers.audio.h a;
    public final /* synthetic */ View b;

    public b(com.quizlet.quizletandroid.managers.audio.h hVar, View view) {
        this.a = hVar;
        this.b = view;
    }

    @Override // android.view.View.AccessibilityDelegate
    public final boolean onRequestSendAccessibilityEvent(ViewGroup viewGroup, View view, AccessibilityEvent accessibilityEvent) {
        Object tag;
        if (accessibilityEvent.getEventType() != 32768 || (tag = view.getTag(R.id.quizlet_tts_url)) == null) {
            return true;
        }
        boolean z = tag instanceof String;
        if (z) {
            String str = (String) tag;
            if (!org.apache.commons.lang3.e.c(str)) {
                this.a.a(str).f(new com.quizlet.background.eventlogging.a(4), new com.quizlet.billing.subscriptions.c(2));
                return false;
            }
        }
        if (z) {
            return true;
        }
        timber.log.c.a(new IllegalStateException("Encountered a non-String value for the Quizlet TTS URL tag " + this.b));
        return true;
    }
}
