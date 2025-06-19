package retrofit2.converter.scalars;

import java.io.IOException;
import okhttp3.J;
import retrofit2.InterfaceC5186k;

/* loaded from: classes3.dex */
public final class b implements InterfaceC5186k {
    public static final b b = new b(0);
    public static final b c = new b(1);
    public static final b d = new b(2);
    public static final b e = new b(3);
    public static final b f = new b(4);
    public static final b g = new b(5);
    public static final b h = new b(6);
    public static final b i = new b(7);
    public static final b j = new b(8);
    public final /* synthetic */ int a;

    public /* synthetic */ b(int i2) {
        this.a = i2;
    }

    @Override // retrofit2.InterfaceC5186k
    public final Object convert(Object obj) throws IOException {
        switch (this.a) {
            case 0:
                return Boolean.valueOf(((J) obj).f());
            case 1:
                return Byte.valueOf(((J) obj).f());
            case 2:
                String strF = ((J) obj).f();
                if (strF.length() == 1) {
                    return Character.valueOf(strF.charAt(0));
                }
                throw new IOException("Expected body of length 1 for Character conversion but was " + strF.length());
            case 3:
                return Double.valueOf(((J) obj).f());
            case 4:
                return Float.valueOf(((J) obj).f());
            case 5:
                return Integer.valueOf(((J) obj).f());
            case 6:
                return Long.valueOf(((J) obj).f());
            case 7:
                return Short.valueOf(((J) obj).f());
            default:
                return ((J) obj).f();
        }
    }
}
