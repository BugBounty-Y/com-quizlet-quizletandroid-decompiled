package retrofit2;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.recyclerview.widget.C1372j;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import java.util.ArrayList;
import java.util.regex.Pattern;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class H {
    public static final char[] l = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    public static final Pattern m = Pattern.compile("(.*/)?(\\.|%2e|%2E){1,2}(/.*)?");
    public final String a;
    public final okhttp3.s b;
    public String c;
    public C1372j d;
    public final com.quizlet.remote.model.notes.e e = new com.quizlet.remote.model.notes.e(13);
    public final com.android.billingclient.api.h f;
    public okhttp3.w g;
    public final boolean h;
    public final com.quizlet.data.interactor.set.c i;
    public final com.quizlet.remote.model.user.a j;
    public okhttp3.F k;

    public H(String str, okhttp3.s sVar, String str2, okhttp3.r rVar, okhttp3.w wVar, boolean z, boolean z2, boolean z3) {
        this.a = str;
        this.b = sVar;
        this.c = str2;
        this.g = wVar;
        this.h = z;
        if (rVar != null) {
            this.f = rVar.e();
        } else {
            this.f = new com.android.billingclient.api.h(3);
        }
        if (z2) {
            this.j = new com.quizlet.remote.model.user.a();
        } else if (z3) {
            com.quizlet.data.interactor.set.c cVar = new com.quizlet.data.interactor.set.c(0);
            this.i = cVar;
            cVar.r(okhttp3.y.f);
        }
    }

    public final void a(String name, String value, boolean z) {
        com.quizlet.remote.model.user.a aVar = this.j;
        if (z) {
            aVar.getClass();
            Intrinsics.checkNotNullParameter(name, "name");
            Intrinsics.checkNotNullParameter(value, "value");
            ((ArrayList) aVar.a).add(okhttp3.o.b(0, 0, 83, name, " \"':;<=>@[]^`{}|/\\?#&!$(),~", true));
            ((ArrayList) aVar.b).add(okhttp3.o.b(0, 0, 83, value, " \"':;<=>@[]^`{}|/\\?#&!$(),~", true));
            return;
        }
        aVar.getClass();
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(value, "value");
        ((ArrayList) aVar.a).add(okhttp3.o.b(0, 0, 91, name, " \"':;<=>@[]^`{}|/\\?#&!$(),~", false));
        ((ArrayList) aVar.b).add(okhttp3.o.b(0, 0, 91, value, " \"':;<=>@[]^`{}|/\\?#&!$(),~", false));
    }

    public final void b(String str, String str2, boolean z) {
        if ("Content-Type".equalsIgnoreCase(str)) {
            try {
                Pattern pattern = okhttp3.w.e;
                this.g = AbstractC3347h2.c(str2);
                return;
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(AbstractC0147y.d("Malformed content type: ", str2), e);
            }
        }
        com.android.billingclient.api.h hVar = this.f;
        if (z) {
            hVar.c(str, str2);
        } else {
            hVar.a(str, str2);
        }
    }

    public final void c(okhttp3.r rVar, okhttp3.F body) {
        com.quizlet.data.interactor.set.c cVar = this.i;
        cVar.getClass();
        Intrinsics.checkNotNullParameter(body, "body");
        Intrinsics.checkNotNullParameter(body, "body");
        if (rVar.a("Content-Type") != null) {
            throw new IllegalArgumentException("Unexpected header: Content-Type");
        }
        if (rVar.a("Content-Length") != null) {
            throw new IllegalArgumentException("Unexpected header: Content-Length");
        }
        cVar.i(new okhttp3.x(rVar, body));
    }

    public final void d(String encodedName, String str, boolean z) {
        String str2 = this.c;
        if (str2 != null) {
            okhttp3.s sVar = this.b;
            C1372j c1372jG = sVar.g(str2);
            this.d = c1372jG;
            if (c1372jG == null) {
                throw new IllegalArgumentException("Malformed URL. Base: " + sVar + ", Relative: " + this.c);
            }
            this.c = null;
        }
        if (!z) {
            this.d.c(encodedName, str);
            return;
        }
        C1372j c1372j = this.d;
        c1372j.getClass();
        Intrinsics.checkNotNullParameter(encodedName, "encodedName");
        if (c1372j.d == null) {
            c1372j.d = new ArrayList();
        }
        ArrayList arrayList = c1372j.d;
        Intrinsics.d(arrayList);
        arrayList.add(okhttp3.o.b(0, 0, 211, encodedName, " \"'<>#&=", true));
        ArrayList arrayList2 = c1372j.d;
        Intrinsics.d(arrayList2);
        arrayList2.add(str != null ? okhttp3.o.b(0, 0, 211, str, " \"'<>#&=", true) : null);
    }
}
