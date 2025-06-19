package kotlin;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class m {
    public static final m a;
    public static final m b;
    public static final m c;
    public static final /* synthetic */ m[] d;

    static {
        m mVar = new m("SYNCHRONIZED", 0);
        a = mVar;
        m mVar2 = new m("PUBLICATION", 1);
        b = mVar2;
        m mVar3 = new m("NONE", 2);
        c = mVar3;
        m[] mVarArr = {mVar, mVar2, mVar3};
        d = mVarArr;
        AbstractC3328d.f(mVarArr);
    }

    public static m valueOf(String str) {
        return (m) Enum.valueOf(m.class, str);
    }

    public static m[] values() {
        return (m[]) d.clone();
    }
}
