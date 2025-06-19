package com.google.common.cache;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public abstract class x {
    public static final u a;
    public static final w b;
    public static final /* synthetic */ x[] c;

    static {
        u uVar = new u();
        a = uVar;
        x xVar = new x() { // from class: com.google.common.cache.v
            @Override // com.google.common.cache.x
            public final com.google.common.base.f a() {
                return com.google.common.base.e.a;
            }

            @Override // com.google.common.cache.x
            public final C b(s sVar, J j, Object obj) {
                return new t(sVar.i, obj, j);
            }
        };
        w wVar = new w();
        b = wVar;
        c = new x[]{uVar, xVar, wVar};
    }

    public static x valueOf(String str) {
        return (x) Enum.valueOf(x.class, str);
    }

    public static x[] values() {
        return (x[]) c.clone();
    }

    public abstract com.google.common.base.f a();

    public abstract C b(s sVar, J j, Object obj);
}
