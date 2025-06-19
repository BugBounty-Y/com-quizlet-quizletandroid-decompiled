package org.wordpress.aztec.util;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.Color;
import android.os.Bundle;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.TextUtils;
import com.amazon.device.ads.DtbConstants;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3336f;
import com.quizlet.quizletandroid.ui.profile.p;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.h;
import kotlin.text.StringsKt;
import org.jsoup.nodes.f;
import org.jsoup.nodes.g;
import org.jsoup.nodes.i;
import org.jsoup.nodes.n;
import org.jsoup.parser.C;
import org.jsoup.parser.g1;

/* loaded from: classes3.dex */
public abstract class b {
    public static final p a = new p(6);

    public static final String a(String html) {
        Intrinsics.checkNotNullParameter(html, "html");
        g gVarN = new com.quizlet.data.repository.course.membership.c(new g1()).n(html, "");
        f fVar = new f();
        fVar.e = false;
        gVarN.getClass();
        gVarN.j = fVar;
        b(gVarN);
        String strM = gVarN.M();
        Intrinsics.checkNotNullExpressionValue(strM, "html(...)");
        return strM;
    }

    public static final void b(g doc) {
        Intrinsics.checkNotNullParameter(doc, "doc");
        C cS = doc.S("b > b");
        Intrinsics.checkNotNullExpressionValue(cS, "select(...)");
        ArrayList arrayList = new ArrayList();
        Iterator it2 = cS.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            if (!((i) next).L()) {
                arrayList.add(next);
            }
        }
        Iterator it3 = arrayList.iterator();
        while (it3.hasNext()) {
            ((i) it3.next()).y();
        }
        C cS2 = doc.S("b > b");
        Intrinsics.checkNotNullExpressionValue(cS2, "select(...)");
        ArrayList arrayList2 = new ArrayList();
        Iterator it4 = cS2.iterator();
        while (it4.hasNext()) {
            Object next2 = it4.next();
            if (((i) next2).L()) {
                arrayList2.add(next2);
            }
        }
        Iterator it5 = arrayList2.iterator();
        while (it5.hasNext()) {
            i iVar = (i) it5.next();
            org.jsoup.helper.b.g(iVar.a);
            if (iVar.f.size() != 0) {
            }
            iVar.a.c(iVar.b, (n[]) iVar.m().toArray(new n[0]));
            iVar.y();
        }
    }

    /* JADX WARN: Type inference failed for: r1v2, types: [java.lang.Object, java.util.Map] */
    public static int c(String colorText) {
        Intrinsics.checkNotNullParameter(colorText, "colorText");
        try {
            if (!TextUtils.isEmpty(colorText) && StringsKt.X(colorText, '@')) {
                Resources system = Resources.getSystem();
                String strSubstring = colorText.substring(1);
                Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                if (system.getIdentifier(strSubstring, "color", DtbConstants.NATIVE_OS_NAME) != 0) {
                    Resources system2 = Resources.getSystem();
                    String strSubstring2 = colorText.substring(1);
                    Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
                    int identifier = system2.getIdentifier(strSubstring2, "color", DtbConstants.NATIVE_OS_NAME);
                    if (identifier != 0) {
                        return system2.getColor(identifier, null);
                    }
                }
            }
            Integer num = (Integer) c.a.get(colorText);
            return num != null ? num.intValue() : Color.parseColor(colorText);
        } catch (Exception e) {
            if (e instanceof IllegalArgumentException ? true : e instanceof StringIndexOutOfBoundsException) {
                return -1;
            }
            throw e;
        }
    }

    public static final Object d(SpannableStringBuilder spannableStringBuilder, Class kind) {
        Object next;
        Intrinsics.checkNotNullParameter(spannableStringBuilder, "<this>");
        Intrinsics.checkNotNullParameter(kind, "kind");
        Object[] spans = spannableStringBuilder.getSpans(0, spannableStringBuilder.length(), kind);
        Intrinsics.d(spans);
        if (spans.length != 0) {
            int length = spans.length;
            h.d.getClass();
            kotlin.ranges.i it2 = new h(length, 1, -1).iterator();
            while (true) {
                if (!it2.c) {
                    next = null;
                    break;
                }
                next = it2.next();
                if (spannableStringBuilder.getSpanFlags(spans[((Number) next).intValue() - 1]) == 17) {
                    break;
                }
            }
            Integer num = (Integer) next;
            if (num != null) {
                return spans[num.intValue() - 1];
            }
        }
        return null;
    }

    public static boolean e(Spannable spannable, int i, int i2, int i3) {
        Intrinsics.checkNotNullParameter(spannable, "spannable");
        if ((((i3 & 240) >> 4) != 3 || i == 0 || i == spannable.length() || spannable.charAt(i + (-1)) == '\n') ? false : true) {
            StringBuilder sbV = android.support.v4.media.session.a.v(i, "PARAGRAPH span must start at paragraph boundary (", " follows ");
            sbV.append(spannable.charAt(i - 1));
            sbV.append(')');
            org.wordpress.android.util.a.c(sbV.toString());
            return true;
        }
        if ((i3 & 15) != 3 || i2 == 0 || i2 == spannable.length() || spannable.charAt(i2 - 1) == '\n') {
            return false;
        }
        StringBuilder sbV2 = android.support.v4.media.session.a.v(i2, "PARAGRAPH span must end at paragraph boundary (", " follows ");
        sbV2.append(spannable.charAt(i2 - 1));
        sbV2.append(')');
        org.wordpress.android.util.a.c(sbV2.toString());
        return true;
    }

    public static void f(String str, Exception exc) {
        StringBuilder sbY = android.support.v4.media.session.a.y("Error trying to write cache for ", str, ". Exception: ");
        sbY.append(exc.getMessage());
        org.wordpress.android.util.a.c(sbY.toString());
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static Object g(String varName, Serializable serializable, Bundle bundle) throws IOException {
        Intrinsics.checkNotNullParameter(varName, "varName");
        Intrinsics.checkNotNullParameter(bundle, "bundle");
        String string = bundle.getString("CACHEFILENAMEKEY_".concat(varName));
        if (string != null && string.length() != 0) {
            File file = new File(string);
            if (file.exists()) {
                FileInputStream fileInputStream = new FileInputStream(file);
                try {
                    ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
                    try {
                        Object object = objectInputStream.readObject();
                        if (object != 0) {
                            serializable = object;
                        }
                        Unit unit = Unit.a;
                        objectInputStream.close();
                        fileInputStream.close();
                        file.delete();
                        return serializable;
                    } finally {
                    }
                } finally {
                }
            }
        }
        return serializable;
    }

    public static void h(Context context, String varName, Serializable serializable, Bundle bundle) throws IOException {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(varName, "varName");
        Intrinsics.checkNotNullParameter(bundle, "bundle");
        try {
            File fileCreateTempFile = File.createTempFile(varName, ".inst", context.getCacheDir());
            fileCreateTempFile.deleteOnExit();
            FileOutputStream fileOutputStream = new FileOutputStream(fileCreateTempFile);
            try {
                ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream);
                try {
                    objectOutputStream.writeObject(serializable);
                    bundle.putString("CACHEFILENAMEKEY_".concat(varName), fileCreateTempFile.getPath());
                    Unit unit = Unit.a;
                    objectOutputStream.close();
                    fileOutputStream.close();
                } finally {
                }
            } catch (Throwable th) {
                try {
                    throw th;
                } catch (Throwable th2) {
                    AbstractC3336f.c(fileOutputStream, th);
                    throw th2;
                }
            }
        } catch (IOException e) {
            f(varName, e);
        } catch (NullPointerException e2) {
            f(varName, e2);
        } catch (SecurityException e3) {
            f(varName, e3);
        }
    }
}
