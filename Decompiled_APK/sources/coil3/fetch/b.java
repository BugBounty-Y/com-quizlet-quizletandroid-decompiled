package coil3.fetch;

import android.content.ContentResolver;
import android.content.Context;
import android.content.res.AssetFileDescriptor;
import android.content.res.Resources;
import android.content.res.XmlResourceParser;
import android.graphics.Bitmap;
import android.graphics.Point;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.VectorDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.util.TypedValue;
import android.webkit.MimeTypeMap;
import androidx.core.content.res.k;
import coil3.decode.p;
import coil3.decode.r;
import coil3.decode.s;
import coil3.n;
import coil3.request.m;
import coil3.util.l;
import coil3.y;
import com.google.android.gms.internal.mlkit_vision_camera.u3;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3479k;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3497n;
import java.io.IOException;
import java.util.List;
import java.util.Locale;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import okio.AbstractC5085b;
import okio.C5091h;
import okio.x;
import org.xmlpull.v1.XmlPullParserException;

/* loaded from: classes.dex */
public final class b implements g {
    public final /* synthetic */ int a;
    public final y b;
    public final m c;

    public /* synthetic */ b(y yVar, m mVar, int i) {
        this.a = i;
        this.b = yVar;
        this.c = mVar;
    }

    @Override // coil3.fetch.g
    public final Object a(kotlin.coroutines.h hVar) throws XmlPullParserException, Resources.NotFoundException, IOException {
        AssetFileDescriptor assetFileDescriptorOpenAssetFileDescriptor;
        List listG;
        int size;
        Integer intOrNull;
        Drawable drawable;
        Bundle bundle = null;
        String mimeTypeFromExtension = null;
        String mimeTypeFromExtension2 = null;
        bundle = null;
        m mVar = this.c;
        y yVar = this.b;
        switch (this.a) {
            case 0:
                String strS = CollectionsKt.S(CollectionsKt.H(1, n.g(yVar)), "/", null, null, null, 62);
                return new i(new s(AbstractC5085b.c(AbstractC5085b.j(mVar.a.getAssets().open(strS))), mVar.f, new coil3.decode.a(strS)), AbstractC3497n.c(strS), coil3.decode.h.c);
            case 1:
                Uri uri = Uri.parse(yVar.a);
                ContentResolver contentResolver = mVar.a.getContentResolver();
                String str = yVar.d;
                if (Intrinsics.b(str, "com.android.contacts") && Intrinsics.b(CollectionsKt.V(n.g(yVar)), "display_photo")) {
                    assetFileDescriptorOpenAssetFileDescriptor = contentResolver.openAssetFileDescriptor(uri, "r");
                    if (assetFileDescriptorOpenAssetFileDescriptor == null) {
                        throw new IllegalStateException(("Unable to find a contact photo associated with '" + uri + "'.").toString());
                    }
                } else if (Build.VERSION.SDK_INT >= 29 && Intrinsics.b(str, "media") && (size = (listG = n.g(yVar)).size()) >= 3 && Intrinsics.b(listG.get(size - 3), "audio") && Intrinsics.b(listG.get(size - 2), "albums")) {
                    coil3.size.h hVar2 = mVar.b;
                    coil3.size.c cVar = hVar2.a;
                    coil3.size.a aVar = cVar instanceof coil3.size.a ? (coil3.size.a) cVar : null;
                    if (aVar != null) {
                        coil3.size.c cVar2 = hVar2.b;
                        coil3.size.a aVar2 = cVar2 instanceof coil3.size.a ? (coil3.size.a) cVar2 : null;
                        if (aVar2 != null) {
                            bundle = new Bundle(1);
                            bundle.putParcelable("android.content.extra.SIZE", new Point(aVar.a, aVar2.a));
                        }
                    }
                    assetFileDescriptorOpenAssetFileDescriptor = contentResolver.openTypedAssetFile(uri, "image/*", bundle, null);
                    if (assetFileDescriptorOpenAssetFileDescriptor == null) {
                        throw new IllegalStateException(("Unable to find a music thumbnail associated with '" + uri + "'.").toString());
                    }
                } else {
                    assetFileDescriptorOpenAssetFileDescriptor = contentResolver.openAssetFileDescriptor(uri, "r");
                    if (assetFileDescriptorOpenAssetFileDescriptor == null) {
                        throw new IllegalStateException(("Unable to open '" + uri + "'.").toString());
                    }
                }
                return new i(new s(AbstractC5085b.c(AbstractC5085b.j(assetFileDescriptorOpenAssetFileDescriptor.createInputStream())), mVar.f, new coil3.decode.g(assetFileDescriptorOpenAssetFileDescriptor)), contentResolver.getType(uri), coil3.decode.h.c);
            case 2:
                int iM = StringsKt.M(yVar.a, ";base64,", 0, false, 6);
                if (iM == -1) {
                    throw new IllegalStateException(("invalid data uri: " + yVar).toString());
                }
                String str2 = yVar.a;
                int iL = StringsKt.L(str2, ':', 0, false, 6);
                if (iL == -1) {
                    throw new IllegalStateException(("invalid data uri: " + yVar).toString());
                }
                String strSubstring = str2.substring(iL + 1, iM);
                Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                byte[] bArrA = kotlin.io.encoding.c.a(kotlin.io.encoding.c.c, str2, iM + 8, 4);
                C5091h c5091h = new C5091h();
                c5091h.n0(bArrA);
                return new i(new s(c5091h, mVar.f, null), strSubstring, coil3.decode.h.b);
            case 3:
                String str3 = x.b;
                String strF = n.f(yVar);
                if (strF == null) {
                    throw new IllegalStateException("filePath == null");
                }
                x xVarF = com.quizlet.quizletandroid.ui.folder.logging.a.f(strF, false);
                p pVarA = u3.a(xVarF, mVar.f, null, null, 28);
                String strC0 = StringsKt.c0(xVarF.b(), "", '.');
                if (!StringsKt.O(strC0)) {
                    String lowerCase = strC0.toLowerCase(Locale.ROOT);
                    Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
                    mimeTypeFromExtension2 = (String) coil3.util.i.a.get(lowerCase);
                    if (mimeTypeFromExtension2 == null) {
                        mimeTypeFromExtension2 = MimeTypeMap.getSingleton().getMimeTypeFromExtension(lowerCase);
                    }
                }
                return new i(pVarA, mimeTypeFromExtension2, coil3.decode.h.c);
            case 4:
                String str4 = yVar.e;
                if (str4 == null) {
                    str4 = "";
                }
                int iL2 = StringsKt.L(str4, '!', 0, false, 6);
                if (iL2 == -1) {
                    throw new IllegalStateException(("Invalid jar:file URI: " + yVar).toString());
                }
                String str5 = x.b;
                String strSubstring2 = str4.substring(0, iL2);
                Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
                x zipPath = com.quizlet.quizletandroid.ui.folder.logging.a.f(strSubstring2, false);
                String strSubstring3 = str4.substring(iL2 + 1, str4.length());
                Intrinsics.checkNotNullExpressionValue(strSubstring3, "substring(...)");
                x xVarF2 = com.quizlet.quizletandroid.ui.folder.logging.a.f(strSubstring3, false);
                okio.n nVar = mVar.f;
                Intrinsics.checkNotNullParameter(nVar, "<this>");
                Intrinsics.checkNotNullParameter(zipPath, "zipPath");
                p pVarA2 = u3.a(xVarF2, okio.internal.b.e(zipPath, nVar, new com.sdk.growthbook.utils.a(29)), null, null, 28);
                String strC02 = StringsKt.c0(xVarF2.b(), "", '.');
                if (!StringsKt.O(strC02)) {
                    String lowerCase2 = strC02.toLowerCase(Locale.ROOT);
                    Intrinsics.checkNotNullExpressionValue(lowerCase2, "toLowerCase(...)");
                    mimeTypeFromExtension = (String) coil3.util.i.a.get(lowerCase2);
                    if (mimeTypeFromExtension == null) {
                        mimeTypeFromExtension = MimeTypeMap.getSingleton().getMimeTypeFromExtension(lowerCase2);
                    }
                }
                return new i(pVarA2, mimeTypeFromExtension, coil3.decode.h.c);
            default:
                String str6 = yVar.d;
                if (str6 != null) {
                    String str7 = StringsKt.O(str6) ? null : str6;
                    if (str7 != null) {
                        String str8 = (String) CollectionsKt.V(n.g(yVar));
                        if (str8 == null || (intOrNull = StringsKt.toIntOrNull(str8)) == null) {
                            throw new IllegalStateException("Invalid android.resource URI: " + yVar);
                        }
                        int iIntValue = intOrNull.intValue();
                        Context context = mVar.a;
                        Resources resources = str7.equals(context.getPackageName()) ? context.getResources() : context.getPackageManager().getResourcesForApplication(str7);
                        TypedValue typedValue = new TypedValue();
                        resources.getValue(iIntValue, typedValue, true);
                        String strC = AbstractC3497n.c(typedValue.string.toString());
                        if (!Intrinsics.b(strC, "text/xml")) {
                            return new i(new s(AbstractC5085b.c(AbstractC5085b.j(resources.openRawResource(iIntValue, new TypedValue()))), mVar.f, new r(str7, iIntValue)), strC, coil3.decode.h.c);
                        }
                        if (str7.equals(context.getPackageName())) {
                            drawable = com.facebook.appevents.g.f(context, iIntValue);
                            if (drawable == null) {
                                throw new IllegalStateException(android.support.v4.media.session.a.f(iIntValue, "Invalid resource ID: ").toString());
                            }
                        } else {
                            XmlResourceParser xml = resources.getXml(iIntValue);
                            int next = xml.next();
                            while (next != 2 && next != 1) {
                                next = xml.next();
                            }
                            if (next != 2) {
                                throw new XmlPullParserException("No start tag found.");
                            }
                            Resources.Theme theme = context.getTheme();
                            ThreadLocal threadLocal = k.a;
                            drawable = resources.getDrawable(iIntValue, theme);
                            if (drawable == null) {
                                throw new IllegalStateException(android.support.v4.media.session.a.f(iIntValue, "Invalid resource ID: ").toString());
                            }
                        }
                        Bitmap.Config[] configArr = l.a;
                        boolean z = (drawable instanceof VectorDrawable) || (drawable instanceof androidx.vectordrawable.graphics.drawable.p);
                        if (z) {
                            drawable = new BitmapDrawable(context.getResources(), AbstractC3479k.b(drawable, (Bitmap.Config) n.e(mVar, coil3.request.i.b), mVar.b, mVar.c, mVar.d == coil3.size.d.b));
                        }
                        return new h(n.c(drawable), z, coil3.decode.h.c);
                    }
                }
                throw new IllegalStateException("Invalid android.resource URI: " + yVar);
        }
    }
}
