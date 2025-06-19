package androidx.camera.core.impl;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class C0 {
    public static final C0 a;
    public static final C0 b;
    public static final C0 c;
    public static final C0 d;
    public static final C0 e;
    public static final C0 f;
    public static final /* synthetic */ C0[] g;

    static {
        C0 c0 = new C0("IMAGE_CAPTURE", 0);
        a = c0;
        C0 c02 = new C0("PREVIEW", 1);
        b = c02;
        C0 c03 = new C0("IMAGE_ANALYSIS", 2);
        c = c03;
        C0 c04 = new C0("VIDEO_CAPTURE", 3);
        d = c04;
        C0 c05 = new C0("STREAM_SHARING", 4);
        e = c05;
        C0 c06 = new C0("METERING_REPEATING", 5);
        f = c06;
        g = new C0[]{c0, c02, c03, c04, c05, c06};
    }

    public static C0 valueOf(String str) {
        return (C0) Enum.valueOf(C0.class, str);
    }

    public static C0[] values() {
        return (C0[]) g.clone();
    }
}
