package com.facebook.appevents.ml;

import kotlin.NoWhenBranchMatchedException;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class c {
    public static final c a;
    public static final c b;
    public static final /* synthetic */ c[] c;

    static {
        c cVar = new c("MTML_INTEGRITY_DETECT", 0);
        a = cVar;
        c cVar2 = new c("MTML_APP_EVENT_PREDICTION", 1);
        b = cVar2;
        c = new c[]{cVar, cVar2};
    }

    public static c valueOf(String str) {
        return (c) Enum.valueOf(c.class, str);
    }

    public static c[] values() {
        return (c[]) c.clone();
    }

    public final String a() {
        int iOrdinal = ordinal();
        if (iOrdinal == 0) {
            return "integrity_detect";
        }
        if (iOrdinal == 1) {
            return "app_event_pred";
        }
        throw new NoWhenBranchMatchedException();
    }

    public final String b() {
        int iOrdinal = ordinal();
        if (iOrdinal == 0) {
            return "MTML_INTEGRITY_DETECT";
        }
        if (iOrdinal == 1) {
            return "MTML_APP_EVENT_PRED";
        }
        throw new NoWhenBranchMatchedException();
    }
}
