package retrofit2.converter.moshi;

import com.squareup.moshi.JsonDataException;
import com.squareup.moshi.l;
import com.squareup.moshi.o;
import com.squareup.moshi.q;
import okhttp3.J;
import okio.InterfaceC5093j;
import okio.k;
import retrofit2.InterfaceC5186k;

/* loaded from: classes3.dex */
public final class c implements InterfaceC5186k {
    public static final k b;
    public final l a;

    static {
        k kVar = k.d;
        b = com.quizlet.quizletandroid.ui.common.images.capture.b.g("EFBBBF");
    }

    public c(l lVar) {
        this.a = lVar;
    }

    @Override // retrofit2.InterfaceC5186k
    public final Object convert(Object obj) {
        J j = (J) obj;
        InterfaceC5093j interfaceC5093jF0 = j.f0();
        try {
            if (interfaceC5093jF0.J(0L, b)) {
                interfaceC5093jF0.skip(r1.a.length);
            }
            q qVar = new q(interfaceC5093jF0);
            Object objA = this.a.a(qVar);
            if (qVar.Q() != o.j) {
                throw new JsonDataException("JSON document was not fully consumed.");
            }
            j.close();
            return objA;
        } catch (Throwable th) {
            j.close();
            throw th;
        }
    }
}
