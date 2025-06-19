package assistantMode.utils.classification.classifierTypes;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class a {
    public static final a a;
    public static final a b;
    public static final a c;
    public static final a d;
    public static final a e;
    public static final a f;
    public static final a g;
    public static final a h;
    public static final /* synthetic */ a[] i;

    static {
        a aVar = new a("EVENT", 0);
        a = aVar;
        a aVar2 = new a("DATE", 1);
        b = aVar2;
        a aVar3 = new a("NUMBER", 2);
        c = aVar3;
        a aVar4 = new a("DOCUMENT", 3);
        d = aVar4;
        a aVar5 = new a("COURT_CASE", 4);
        e = aVar5;
        a aVar6 = new a("NAME", 5);
        f = aVar6;
        a aVar7 = new a("ORGANIZATION", 6);
        g = aVar7;
        a aVar8 = new a("BELIEF_SYSTEM", 7);
        h = aVar8;
        a[] aVarArr = {aVar, aVar2, aVar3, aVar4, aVar5, aVar6, aVar7, aVar8};
        i = aVarArr;
        AbstractC3328d.f(aVarArr);
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) i.clone();
    }
}
