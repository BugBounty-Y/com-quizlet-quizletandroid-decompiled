package coil3.fetch;

import android.graphics.Bitmap;
import android.graphics.drawable.Drawable;
import coil3.n;
import coil3.request.m;
import coil3.u;
import coil3.util.l;
import coil3.y;
import java.nio.ByteBuffer;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a implements f {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // coil3.fetch.f
    public final g a(Object obj, m mVar, u uVar) {
        int i = 0;
        int i2 = 1;
        int i3 = 2;
        int i4 = 3;
        switch (this.a) {
            case 0:
                y yVar = (y) obj;
                Bitmap.Config[] configArr = l.a;
                if (Intrinsics.b(yVar.c, "file") && Intrinsics.b(CollectionsKt.firstOrNull(n.g(yVar)), "android_asset")) {
                    return new b(yVar, mVar, i);
                }
                return null;
            case 1:
                return new c((Bitmap) obj, mVar, i);
            case 2:
                return new c((byte[]) obj, mVar, i2);
            case 3:
                return new c((ByteBuffer) obj, mVar, i3);
            case 4:
                y yVar2 = (y) obj;
                if (Intrinsics.b(yVar2.c, "content")) {
                    return new b(yVar2, mVar, i2);
                }
                return null;
            case 5:
                y yVar3 = (y) obj;
                if (Intrinsics.b(yVar3.c, "data")) {
                    return new b(yVar3, mVar, i3);
                }
                return null;
            case 6:
                return new c((Drawable) obj, mVar, i4);
            case 7:
                y yVar4 = (y) obj;
                String str = yVar4.c;
                if ((str != null && !str.equals("file")) || yVar4.e == null) {
                    return null;
                }
                Bitmap.Config[] configArr2 = l.a;
                if (Intrinsics.b(yVar4.c, "file") && Intrinsics.b(CollectionsKt.firstOrNull(n.g(yVar4)), "android_asset")) {
                    return null;
                }
                return new b(yVar4, mVar, i4);
            case 8:
                y yVar5 = (y) obj;
                if (Intrinsics.b(yVar5.c, "jar:file")) {
                    return new b(yVar5, mVar, 4);
                }
                return null;
            default:
                y yVar6 = (y) obj;
                if (Intrinsics.b(yVar6.c, "android.resource")) {
                    return new b(yVar6, mVar, 5);
                }
                return null;
        }
    }
}
