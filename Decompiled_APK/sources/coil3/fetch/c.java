package coil3.fetch;

import android.graphics.Bitmap;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.VectorDrawable;
import androidx.vectordrawable.graphics.drawable.p;
import coil3.decode.s;
import coil3.n;
import coil3.request.m;
import coil3.util.l;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3479k;
import java.nio.ByteBuffer;
import okio.AbstractC5085b;
import okio.C5091h;

/* loaded from: classes.dex */
public final class c implements g {
    public final /* synthetic */ int a;
    public final m b;
    public final Object c;

    public /* synthetic */ c(Object obj, m mVar, int i) {
        this.a = i;
        this.c = obj;
        this.b = mVar;
    }

    @Override // coil3.fetch.g
    public final Object a(kotlin.coroutines.h hVar) {
        m mVar = this.b;
        Object obj = this.c;
        switch (this.a) {
            case 0:
                return new h(n.c(new BitmapDrawable(mVar.a.getResources(), (Bitmap) obj)), false, coil3.decode.h.b);
            case 1:
                C5091h c5091h = new C5091h();
                c5091h.n0((byte[]) obj);
                return new i(new s(c5091h, mVar.f, null), null, coil3.decode.h.b);
            case 2:
                ByteBuffer byteBuffer = (ByteBuffer) obj;
                return new i(new s(AbstractC5085b.c(new d(byteBuffer)), mVar.f, new coil3.decode.f(byteBuffer)), null, coil3.decode.h.b);
            default:
                Bitmap.Config[] configArr = l.a;
                Drawable bitmapDrawable = (Drawable) obj;
                boolean z = (bitmapDrawable instanceof VectorDrawable) || (bitmapDrawable instanceof p);
                if (z) {
                    bitmapDrawable = new BitmapDrawable(mVar.a.getResources(), AbstractC3479k.b(bitmapDrawable, coil3.request.i.a(mVar), mVar.b, mVar.c, mVar.d == coil3.size.d.b));
                }
                return new h(n.c(bitmapDrawable), z, coil3.decode.h.b);
        }
    }
}
