package com.google.android.gms.internal.ads;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class Jr {
    public static final Jr a;
    public static final /* synthetic */ Jr[] b;

    /* JADX INFO: Fake field, exist only in values array */
    Jr EF0;

    static {
        Jr jr = new Jr("VIDEO_CONTROLS", 0);
        Jr jr2 = new Jr("CLOSE_AD", 1);
        Jr jr3 = new Jr("NOT_VISIBLE", 2);
        a = jr3;
        b = new Jr[]{jr, jr2, jr3, new Jr("OTHER", 3)};
    }

    public static Jr[] values() {
        return (Jr[]) b.clone();
    }
}
