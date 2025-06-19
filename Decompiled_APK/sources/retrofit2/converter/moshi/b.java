package retrofit2.converter.moshi;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import com.squareup.moshi.l;
import com.squareup.moshi.s;
import java.io.EOFException;
import java.util.regex.Pattern;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.D;
import okhttp3.w;
import okio.C5091h;
import okio.k;
import retrofit2.InterfaceC5186k;

/* loaded from: classes3.dex */
public final class b implements InterfaceC5186k {
    public static final w b;
    public final l a;

    static {
        Pattern pattern = w.e;
        b = AbstractC3347h2.c("application/json; charset=UTF-8");
    }

    public b(l lVar) {
        this.a = lVar;
    }

    @Override // retrofit2.InterfaceC5186k
    public final Object convert(Object obj) throws EOFException {
        l lVar = this.a;
        C5091h c5091h = new C5091h();
        lVar.g(new s(c5091h), obj);
        k content = c5091h.D(c5091h.b);
        Intrinsics.checkNotNullParameter(content, "content");
        Intrinsics.checkNotNullParameter(content, "<this>");
        return new D(b, content, 1);
    }
}
