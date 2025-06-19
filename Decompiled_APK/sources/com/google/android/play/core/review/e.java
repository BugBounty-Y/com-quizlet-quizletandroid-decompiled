package com.google.android.play.core.review;

import android.os.Process;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;

/* loaded from: classes2.dex */
public abstract class e {
    public static final HashMap a;

    static {
        new HashSet(Arrays.asList(com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_NATIVE, "unity"));
        a = new HashMap();
        android.support.v4.media.session.a.j("UID: [", Process.myUid(), "]  PID: [", "] ", Process.myPid()).concat("PlayCoreVersion");
    }
}
