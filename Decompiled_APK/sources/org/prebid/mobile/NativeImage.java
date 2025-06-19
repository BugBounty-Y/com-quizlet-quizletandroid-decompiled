package org.prebid.mobile;

/* loaded from: classes3.dex */
public class NativeImage {
    public final int a;
    public final String b;

    /* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
    /* JADX WARN: Unknown enum class pattern. Please report as an issue! */
    public static final class Type {
        public static final Type a;
        public static final Type b;
        public static final Type c;
        public static final /* synthetic */ Type[] d;

        static {
            Type type = new Type("ICON", 0);
            a = type;
            Type type2 = new Type("MAIN_IMAGE", 1);
            b = type2;
            Type type3 = new Type("CUSTOM", 2);
            c = type3;
            d = new Type[]{type, type2, type3};
        }

        public static Type valueOf(String str) {
            return (Type) Enum.valueOf(Type.class, str);
        }

        public static Type[] values() {
            return (Type[]) d.clone();
        }
    }

    public NativeImage(int i, String str) {
        this.a = i;
        this.b = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && getClass() == obj.getClass()) {
            NativeImage nativeImage = (NativeImage) obj;
            if (this.a == nativeImage.a && this.b.equals(nativeImage.b)) {
                return true;
            }
        }
        return false;
    }
}
