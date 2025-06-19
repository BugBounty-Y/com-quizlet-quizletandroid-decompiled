package grading.core.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class a {
    public static final a a;
    public static final a b;
    public static final /* synthetic */ a[] c;

    static {
        a aVar = new a("ACCEPT_PARTIAL_ANSWERS", 0);
        a = aVar;
        a aVar2 = new a("ACCEPT_ANSWERS_WITH_TYPOS", 1);
        b = aVar2;
        a[] aVarArr = {aVar, aVar2, new a("ACCEPT_SMART_GRADING", 2), new a("ALLOW_RETRY", 3)};
        c = aVarArr;
        AbstractC3328d.f(aVarArr);
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) c.clone();
    }
}
