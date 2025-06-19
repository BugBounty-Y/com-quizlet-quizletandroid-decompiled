package retrofit2;

import java.lang.reflect.Method;
import java.util.Map;

/* loaded from: classes3.dex */
public final class y extends S {
    public final /* synthetic */ int d;
    public final Method e;
    public final int f;
    public final boolean g;

    public /* synthetic */ y(Method method, int i, boolean z, int i2) {
        this.d = i2;
        this.e = method;
        this.f = i;
        this.g = z;
    }

    @Override // retrofit2.S
    public final void a(H h, Object obj) {
        switch (this.d) {
            case 0:
                Map map = (Map) obj;
                Method method = this.e;
                int i = this.f;
                if (map == null) {
                    throw S.p(method, i, "Field map was null.", new Object[0]);
                }
                for (Map.Entry entry : map.entrySet()) {
                    String str = (String) entry.getKey();
                    if (str == null) {
                        throw S.p(method, i, "Field map contained null key.", new Object[0]);
                    }
                    Object value = entry.getValue();
                    if (value == null) {
                        throw S.p(method, i, android.support.v4.media.session.a.B("Field map contained null value for key '", str, "'."), new Object[0]);
                    }
                    String string = value.toString();
                    if (string == null) {
                        throw S.p(method, i, "Field map value '" + value + "' converted to null by " + C5176a.class.getName() + " for key '" + str + "'.", new Object[0]);
                    }
                    h.a(str, string, this.g);
                }
                return;
            case 1:
                Map map2 = (Map) obj;
                Method method2 = this.e;
                int i2 = this.f;
                if (map2 == null) {
                    throw S.p(method2, i2, "Header map was null.", new Object[0]);
                }
                for (Map.Entry entry2 : map2.entrySet()) {
                    String str2 = (String) entry2.getKey();
                    if (str2 == null) {
                        throw S.p(method2, i2, "Header map contained null key.", new Object[0]);
                    }
                    Object value2 = entry2.getValue();
                    if (value2 == null) {
                        throw S.p(method2, i2, android.support.v4.media.session.a.B("Header map contained null value for key '", str2, "'."), new Object[0]);
                    }
                    h.b(str2, value2.toString(), this.g);
                }
                return;
            default:
                Map map3 = (Map) obj;
                Method method3 = this.e;
                int i3 = this.f;
                if (map3 == null) {
                    throw S.p(method3, i3, "Query map was null", new Object[0]);
                }
                for (Map.Entry entry3 : map3.entrySet()) {
                    String str3 = (String) entry3.getKey();
                    if (str3 == null) {
                        throw S.p(method3, i3, "Query map contained null key.", new Object[0]);
                    }
                    Object value3 = entry3.getValue();
                    if (value3 == null) {
                        throw S.p(method3, i3, android.support.v4.media.session.a.B("Query map contained null value for key '", str3, "'."), new Object[0]);
                    }
                    String string2 = value3.toString();
                    if (string2 == null) {
                        throw S.p(method3, i3, "Query map value '" + value3 + "' converted to null by " + C5176a.class.getName() + " for key '" + str3 + "'.", new Object[0]);
                    }
                    h.d(str3, string2, this.g);
                }
                return;
        }
    }
}
