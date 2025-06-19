package com.perimeterx.mobile_sdk.models;

import java.util.ArrayList;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class f {
    public final String a;
    public final String b;
    public final ArrayList c;
    public final ReentrantLock d;

    public f(String sid, String vid, ArrayList cookies) {
        Intrinsics.checkNotNullParameter(sid, "sid");
        Intrinsics.checkNotNullParameter(vid, "vid");
        Intrinsics.checkNotNullParameter(cookies, "cookies");
        this.a = sid;
        this.b = vid;
        this.c = cookies;
        this.d = new ReentrantLock();
    }
}
