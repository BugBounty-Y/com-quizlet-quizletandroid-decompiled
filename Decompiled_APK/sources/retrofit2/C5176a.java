package retrofit2;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.List;
import kotlin.Unit;

/* renamed from: retrofit2.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public class C5176a implements InterfaceC5186k {
    public static final C5176a b = new C5176a(0);
    public static final C5176a c = new C5176a(1);
    public static final C5176a d = new C5176a(2);
    public static final C5176a e = new C5176a(3);
    public static final C5176a f = new C5176a(4);
    public static final C5176a g = new C5176a(5);
    public final /* synthetic */ int a;

    public /* synthetic */ C5176a(int i) {
        this.a = i;
    }

    public List a(androidx.core.os.d dVar) {
        return Collections.singletonList(new com.quizlet.remote.service.G(dVar));
    }

    public List b() {
        return Collections.EMPTY_LIST;
    }

    public String c(Method method, int i) {
        return "parameter #" + (i + 1);
    }

    /* JADX WARN: Finally extract failed */
    @Override // retrofit2.InterfaceC5186k
    public Object convert(Object obj) {
        switch (this.a) {
            case 0:
                return obj.toString();
            case 1:
                okhttp3.J j = (okhttp3.J) obj;
                try {
                    okhttp3.I iD = S.d(j);
                    j.close();
                    return iD;
                } catch (Throwable th) {
                    j.close();
                    throw th;
                }
            case 2:
                return (okhttp3.F) obj;
            case 3:
                return (okhttp3.J) obj;
            case 4:
                ((okhttp3.J) obj).close();
                return Unit.a;
            default:
                ((okhttp3.J) obj).close();
                return null;
        }
    }

    public Object d(Class cls, Object obj, Method method, Object[] objArr) {
        throw new AssertionError();
    }

    public boolean e(Method method) {
        return false;
    }
}
