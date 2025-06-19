package com.perimeterx.mobile_sdk.detections.device.touch_interception;

import android.view.MotionEvent;
import kotlin.jvm.internal.J;

/* loaded from: classes2.dex */
public final class c extends kotlin.coroutines.jvm.internal.c {
    public MotionEvent j;
    public J k;
    public kotlinx.coroutines.sync.c l;
    public /* synthetic */ Object m;
    public int n;

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.n |= Integer.MIN_VALUE;
        return e.a(null, this);
    }
}
