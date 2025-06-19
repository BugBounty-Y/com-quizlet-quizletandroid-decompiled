package com.quizlet.quizletandroid.util;

import android.content.Context;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityManager;
import com.quizlet.db.data.models.persisted.DBGroupMembership;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class d implements io.reactivex.rxjava3.functions.h {
    public static final d a = new d();

    public static void a(Context context, CharSequence charSequence) {
        AccessibilityManager accessibilityManager = (AccessibilityManager) context.getSystemService("accessibility");
        if (accessibilityManager.isEnabled()) {
            AccessibilityEvent accessibilityEventObtain = AccessibilityEvent.obtain();
            accessibilityEventObtain.setEventType(16384);
            accessibilityEventObtain.getText().add(charSequence);
            accessibilityManager.sendAccessibilityEvent(accessibilityEventObtain);
        }
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        DBGroupMembership p0 = (DBGroupMembership) obj;
        Intrinsics.checkNotNullParameter(p0, "p0");
        return Long.valueOf(p0.getClassId());
    }
}
