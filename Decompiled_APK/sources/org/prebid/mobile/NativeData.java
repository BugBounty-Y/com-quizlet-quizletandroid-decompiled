package org.prebid.mobile;

/* loaded from: classes3.dex */
public class NativeData {
    public final int a;
    public final String b;

    /* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
    /* JADX WARN: Unknown enum class pattern. Please report as an issue! */
    public static final class Type {
        public static final Type a;
        public static final Type b;
        public static final Type c;
        public static final Type d;
        public static final Type e;
        public static final /* synthetic */ Type[] f;

        static {
            Type type = new Type("SPONSORED_BY", 0);
            a = type;
            Type type2 = new Type("DESCRIPTION", 1);
            b = type2;
            Type type3 = new Type("CALL_TO_ACTION", 2);
            c = type3;
            Type type4 = new Type("RATING", 3);
            d = type4;
            Type type5 = new Type("CUSTOM", 4);
            e = type5;
            f = new Type[]{type, type2, type3, type4, type5};
        }

        public static Type valueOf(String str) {
            return (Type) Enum.valueOf(Type.class, str);
        }

        public static Type[] values() {
            return (Type[]) f.clone();
        }
    }

    public NativeData(int i, String str) {
        this.a = i;
        this.b = str;
    }

    public final Type a() {
        int i = this.a;
        return i != 1 ? i != 2 ? i != 3 ? i != 12 ? Type.e : Type.c : Type.d : Type.b : Type.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && getClass() == obj.getClass()) {
            NativeData nativeData = (NativeData) obj;
            if (this.a == nativeData.a && this.b.equals(nativeData.b)) {
                return true;
            }
        }
        return false;
    }
}
