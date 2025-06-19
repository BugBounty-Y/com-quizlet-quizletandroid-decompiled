package com.quizlet.data.repository.explanations.question;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.text.SpannableStringBuilder;
import androidx.camera.core.impl.C0186z;
import com.braze.requests.framework.o;
import com.facebook.appevents.g;
import com.google.android.gms.internal.ads.AbstractC2330lu;
import com.google.android.gms.internal.ads.Aw;
import com.google.android.gms.internal.ads.Bu;
import com.google.android.gms.internal.ads.C2173i7;
import com.google.android.gms.internal.ads.C2215j7;
import com.google.android.gms.internal.ads.C2244ju;
import com.google.android.gms.internal.ads.C2301l7;
import com.google.android.gms.internal.ads.C2344m7;
import com.google.android.gms.internal.ads.C2466p0;
import com.google.android.gms.internal.ads.C2557r6;
import com.google.android.gms.internal.ads.C2600s6;
import com.google.android.gms.internal.ads.C2604sA;
import com.google.android.gms.internal.ads.C2811x2;
import com.google.android.gms.internal.ads.C2883yp;
import com.google.android.gms.internal.ads.EnumC2515q6;
import com.google.android.gms.internal.ads.Gg;
import com.google.android.gms.internal.ads.Gw;
import com.google.android.gms.internal.ads.H6;
import com.google.android.gms.internal.ads.Hw;
import com.google.android.gms.internal.ads.InterfaceC1818a2;
import com.google.android.gms.internal.ads.InterfaceC2386n6;
import com.google.android.gms.internal.ads.Kn;
import com.google.android.gms.internal.ads.X1;
import com.google.android.gms.internal.ads.Yo;
import com.google.android.gms.internal.ads.Yx;
import com.google.android.gms.internal.mlkit_vision_camera.C2;
import com.google.android.gms.internal.mlkit_vision_camera.H2;
import com.google.android.gms.internal.mlkit_vision_camera.M2;
import com.google.android.gms.internal.mlkit_vision_camera.N2;
import com.google.android.gms.internal.mlkit_vision_camera.O2;
import com.google.android.gms.internal.mlkit_vision_camera.P2;
import com.google.android.gms.internal.mlkit_vision_camera.Q2;
import com.google.android.gms.internal.mlkit_vision_camera.R2;
import com.google.android.gms.internal.mlkit_vision_camera.S2;
import com.google.android.gms.internal.mlkit_vision_camera.X2;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.zip.Inflater;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.CollectionsKt;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;
import org.wordpress.aztec.C5146b;
import org.wordpress.aztec.EnumC5145a;
import org.wordpress.aztec.formatting.e;
import org.wordpress.aztec.formatting.f;
import org.wordpress.aztec.formatting.h;
import org.wordpress.aztec.spans.A;
import org.wordpress.aztec.spans.AbstractC5167o;
import org.wordpress.aztec.spans.AztecBackgroundColorSpan;
import org.wordpress.aztec.spans.AztecStrikethroughSpan;
import org.wordpress.aztec.spans.AztecTaskListSpan;
import org.wordpress.aztec.spans.C;
import org.wordpress.aztec.spans.C5153a;
import org.wordpress.aztec.spans.C5162j;
import org.wordpress.aztec.spans.C5163k;
import org.wordpress.aztec.spans.C5164l;
import org.wordpress.aztec.spans.C5166n;
import org.wordpress.aztec.spans.C5175x;
import org.wordpress.aztec.spans.K;
import org.wordpress.aztec.spans.M;
import org.wordpress.aztec.spans.r;
import org.wordpress.aztec.spans.y;
import org.wordpress.aztec.spans.z;
import org.wordpress.aztec.util.b;
import org.xml.sax.Attributes;
import timber.log.c;

/* loaded from: classes2.dex */
public final class a implements InterfaceC1818a2, InterfaceC2386n6 {
    public Object a;
    public Object b;
    public Object c;
    public Object d;

    public /* synthetic */ a() {
        this.a = null;
        this.b = null;
        this.c = null;
        this.d = null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1818a2
    public void a(byte[] bArr, int i, int i2, C0186z c0186z) {
        Bu buS;
        Rect rect;
        int i3;
        int i4 = 4;
        Kn kn = (Kn) this.a;
        kn.h(i + i2, bArr);
        kn.j(i);
        if (((Inflater) this.d) == null) {
            this.d = new Inflater();
        }
        Inflater inflater = (Inflater) this.d;
        Kn kn2 = (Kn) this.b;
        if (Yo.f(kn, kn2, inflater)) {
            kn.h(kn2.c, kn2.a);
        }
        C2811x2 c2811x2 = (C2811x2) this.c;
        c2811x2.c = false;
        Gg gg = null;
        c2811x2.g = null;
        c2811x2.h = -1;
        c2811x2.i = -1;
        int iS = kn.s();
        if (iS >= 2 && kn.D() == iS) {
            int[] iArr = c2811x2.d;
            if (iArr != null && c2811x2.b) {
                kn.k(kn.D() - 2);
                int iD = kn.D();
                while (kn.b < iD && kn.s() > 0) {
                    int iZ = kn.z();
                    int[] iArr2 = c2811x2.a;
                    switch (iZ) {
                        case 3:
                            i3 = i4;
                            if (kn.s() < 2) {
                                break;
                            } else {
                                int iZ2 = kn.z();
                                int iZ3 = kn.z();
                                int i5 = iZ2 >> 4;
                                if (i5 >= iArr.length) {
                                    i5 = 0;
                                }
                                iArr2[3] = iArr[i5];
                                int i6 = iZ2 & 15;
                                if (i6 >= iArr.length) {
                                    i6 = 0;
                                }
                                iArr2[2] = iArr[i6];
                                int i7 = iZ3 >> 4;
                                if (i7 >= iArr.length) {
                                    i7 = 0;
                                }
                                iArr2[1] = iArr[i7];
                                int i8 = iZ3 & 15;
                                if (i8 >= iArr.length) {
                                    i8 = 0;
                                }
                                iArr2[0] = iArr[i8];
                                c2811x2.c = true;
                                i4 = i3;
                            }
                        case 4:
                            i3 = i4;
                            if (kn.s() < 2 || !c2811x2.c) {
                                break;
                            } else {
                                int iZ4 = kn.z();
                                int iZ5 = kn.z();
                                iArr2[3] = C2811x2.a(iArr2[3], iZ4 >> 4);
                                iArr2[2] = C2811x2.a(iArr2[2], iZ4 & 15);
                                iArr2[1] = C2811x2.a(iArr2[1], iZ5 >> 4);
                                iArr2[0] = C2811x2.a(iArr2[0], iZ5 & 15);
                                i4 = i3;
                            }
                            break;
                        case 5:
                            if (kn.s() < 6) {
                                break;
                            } else {
                                int iZ6 = kn.z();
                                int iZ7 = kn.z();
                                int i9 = iZ7 >> 4;
                                int iZ8 = ((iZ7 & 15) << 8) | kn.z();
                                int iZ9 = kn.z();
                                int iZ10 = kn.z();
                                i3 = i4;
                                c2811x2.g = new Rect((iZ6 << i4) | i9, (iZ9 << i4) | (iZ10 >> 4), iZ8 + 1, (((iZ10 & 15) << 8) | kn.z()) + 1);
                                i4 = i3;
                            }
                        case 6:
                            if (kn.s() < i4) {
                                break;
                            } else {
                                c2811x2.h = kn.D();
                                c2811x2.i = kn.D();
                            }
                    }
                }
            }
            if (c2811x2.d != null && c2811x2.b && c2811x2.c && (rect = c2811x2.g) != null && c2811x2.h != -1 && c2811x2.i != -1 && rect.width() >= 2 && c2811x2.g.height() >= 2) {
                Rect rect2 = c2811x2.g;
                int[] iArr3 = new int[rect2.height() * rect2.width()];
                C2466p0 c2466p0 = new C2466p0();
                kn.j(c2811x2.h);
                c2466p0.q(kn);
                c2811x2.b(c2466p0, true, rect2, iArr3);
                kn.j(c2811x2.i);
                c2466p0.q(kn);
                c2811x2.b(c2466p0, false, rect2, iArr3);
                gg = new Gg(null, null, null, Bitmap.createBitmap(iArr3, rect2.width(), rect2.height(), Bitmap.Config.ARGB_8888), rect2.top / c2811x2.f, 0, 0, rect2.left / c2811x2.e, 0, Integer.MIN_VALUE, -3.4028235E38f, rect2.width() / c2811x2.e, rect2.height() / c2811x2.f, Integer.MIN_VALUE, DefinitionKt.NO_Float_VALUE);
            }
        }
        if (gg != null) {
            buS = AbstractC2330lu.s(gg);
        } else {
            C2244ju c2244ju = AbstractC2330lu.b;
            buS = Bu.e;
        }
        c0186z.mo10b(new X1(buS, -9223372036854775807L, 5000000L));
    }

    public void b(SpannableStringBuilder spannableStringBuilder, Class cls) {
        ArrayList arrayList = (ArrayList) this.d;
        Object objD = (arrayList.size() <= 0 || !cls.equals(arrayList.get(arrayList.size() + (-1)).getClass())) ? b.d(spannableStringBuilder, cls) : arrayList.remove(arrayList.size() - 1);
        int spanStart = spannableStringBuilder.getSpanStart(objD);
        int length = spannableStringBuilder.length();
        if (spanStart != length) {
            spannableStringBuilder.setSpan(objD, spanStart, length, 33);
            if (objD instanceof C) {
                ((C) objD).h(spannableStringBuilder, spanStart, length);
                return;
            }
            return;
        }
        if (spanStart == length && K.class.isAssignableFrom(cls)) {
            if (z.class.isAssignableFrom(cls)) {
                spannableStringBuilder.append((char) 65279);
            } else {
                spannableStringBuilder.append(C2.c);
            }
            spannableStringBuilder.setSpan(objD, spanStart, spannableStringBuilder.length(), 33);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2386n6
    public void c(C2301l7 c2301l7) {
        C2557r6 c2557r6 = (C2557r6) ((C2344m7) c2301l7.b).F().l();
        c2557r6.e();
        C2600s6.w((C2600s6) c2557r6.b, (EnumC2515q6) this.a);
        c2301l7.e();
        C2344m7.y((C2344m7) c2301l7.b, (C2600s6) c2557r6.c());
        C2173i7 c2173i7 = (C2173i7) ((C2344m7) c2301l7.b).G().l();
        c2173i7.e();
        C2215j7.w((C2215j7) c2173i7.b, (String) this.b);
        H6 h6 = (H6) this.c;
        c2173i7.e();
        C2215j7.x((C2215j7) c2173i7.b, h6);
        c2301l7.e();
        C2344m7.A((C2344m7) c2301l7.b, (C2215j7) c2173i7.c());
        c2301l7.e();
        C2344m7.D((C2344m7) c2301l7.b, (String) this.d);
    }

    public Object d(Integer num) {
        Object value;
        try {
            value = ((u) this.d).getValue();
        } catch (Exception e) {
            c.a.q(e, "Unexpected error when checking growthbook feature: ".concat((String) this.b), new Object[0]);
        }
        return value == null ? num : value;
    }

    public void e(SpannableStringBuilder spannableStringBuilder, boolean z, M m) {
        if (z) {
            h(spannableStringBuilder, m);
        } else {
            b(spannableStringBuilder, m.getClass());
        }
    }

    public void f(boolean z, SpannableStringBuilder spannableStringBuilder, AbstractC5167o abstractC5167o) {
        if (!z) {
            b(spannableStringBuilder, C5166n.class);
            b(spannableStringBuilder, abstractC5167o.getClass());
        } else {
            h(spannableStringBuilder, abstractC5167o);
            h(spannableStringBuilder, new C5166n(abstractC5167o));
            spannableStringBuilder.append(C2.e);
        }
    }

    public boolean g(boolean z, String tag, SpannableStringBuilder output, Context context, Attributes attributes, int i) {
        M mC;
        C5175x c5175x;
        M aztecBackgroundColorSpan;
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(output, "output");
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        ArrayList arrayList = new ArrayList();
        Iterator it2 = ((List) this.a).iterator();
        while (it2.hasNext()) {
            if (it2.next() != null) {
                throw new ClassCastException();
            }
        }
        ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
        Iterator it3 = arrayList.iterator();
        while (it3.hasNext()) {
            if (it3.next() != null) {
                throw new ClassCastException();
            }
            Intrinsics.e(null, "null cannot be cast to non-null type org.wordpress.aztec.plugins.html2visual.IHtmlTagHandler");
            arrayList2.add(null);
        }
        Iterator it4 = arrayList2.iterator();
        if (it4.hasNext()) {
            throw android.support.v4.media.session.a.d(it4);
        }
        Locale locale = Locale.getDefault();
        Intrinsics.checkNotNullExpressionValue(locale, "getDefault(...)");
        String lowerCase = tag.toLowerCase(locale);
        Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
        boolean zB = Intrinsics.b(lowerCase, "li");
        EnumC5145a alignmentRendering = (EnumC5145a) this.b;
        if (zB) {
            e(output, z, N2.b(i, alignmentRendering, new C5146b(attributes), null, 8));
            return true;
        }
        if (Intrinsics.b(lowerCase, "s") ? true : Intrinsics.b(lowerCase, "strike") ? true : Intrinsics.b(lowerCase, "del")) {
            e(output, z, new AztecStrikethroughSpan(tag, new C5146b(attributes)));
            return true;
        }
        boolean zB2 = Intrinsics.b(lowerCase, "span");
        ArrayList arrayList3 = (ArrayList) this.d;
        if (zB2) {
            C5146b attributes2 = new C5146b(attributes);
            if (H2.b(attributes2) || (!arrayList3.isEmpty() && (CollectionsKt.U(arrayList3) instanceof AztecBackgroundColorSpan))) {
                String strD = H2.d("background-color", attributes2);
                Object obj = org.wordpress.aztec.util.c.a;
                aztecBackgroundColorSpan = new AztecBackgroundColorSpan(b.c(strD));
            } else {
                Intrinsics.checkNotNullParameter(tag, "tag");
                Intrinsics.checkNotNullParameter(attributes2, "attributes");
                Intrinsics.checkNotNullParameter(alignmentRendering, "alignmentRendering");
                int iOrdinal = alignmentRendering.ordinal();
                if (iOrdinal == 0) {
                    Intrinsics.checkNotNullParameter(tag, "tag");
                    Intrinsics.checkNotNullParameter(attributes2, "attributes");
                    aztecBackgroundColorSpan = new A(tag, attributes2, i);
                } else {
                    if (iOrdinal != 1) {
                        throw new NoWhenBranchMatchedException();
                    }
                    aztecBackgroundColorSpan = new z(tag, attributes2, i);
                }
            }
            e(output, z, aztecBackgroundColorSpan);
            return true;
        }
        if (Intrinsics.b(lowerCase, "div") ? true : Intrinsics.b(lowerCase, "figure") ? true : Intrinsics.b(lowerCase, "figcaption") ? true : Intrinsics.b(lowerCase, "section")) {
            C5146b attributes3 = new C5146b(attributes);
            Intrinsics.checkNotNullParameter(tag, "tag");
            Intrinsics.checkNotNullParameter(alignmentRendering, "alignmentRendering");
            Intrinsics.checkNotNullParameter(attributes3, "attributes");
            int iOrdinal2 = alignmentRendering.ordinal();
            if (iOrdinal2 == 0) {
                Intrinsics.checkNotNullParameter(tag, "tag");
                Intrinsics.checkNotNullParameter(attributes3, "attributes");
                y yVar = new y(tag, attributes3, i);
                yVar.f = attributes3;
                yVar.g = i;
                c5175x = yVar;
            } else {
                if (iOrdinal2 != 1) {
                    throw new NoWhenBranchMatchedException();
                }
                c5175x = new C5175x(tag, attributes3, i);
            }
            e(output, z, c5175x);
            return true;
        }
        if (Intrinsics.b(lowerCase, "ul")) {
            Object objV = CollectionsKt.V(arrayList3);
            Intrinsics.checkNotNullParameter(attributes, "<this>");
            if (Intrinsics.b(attributes.getValue(DBUserFields.Names.USER_UPGRADE_TYPE), "task-list") || (!z && (objV instanceof AztecTaskListSpan))) {
                Intrinsics.checkNotNullParameter(attributes, "attributes");
                mC = R2.c(i, alignmentRendering, new C5146b(attributes), context, new e(0, 0, 0, 0, 0));
            } else {
                Intrinsics.checkNotNullParameter(attributes, "attributes");
                mC = S2.e(i, alignmentRendering, new C5146b(attributes), new e(0, 0, 0, 0, 0));
            }
            e(output, z, mC);
            return true;
        }
        if (Intrinsics.b(lowerCase, "ol")) {
            e(output, z, O2.a(i, alignmentRendering, new C5146b(attributes), new e(0, 0, 0, 0, 0)));
            return true;
        }
        if (Intrinsics.b(lowerCase, "blockquote")) {
            e(output, z, Q2.a(i, new C5146b(attributes), alignmentRendering, new h(0, 0, 0, DefinitionKt.NO_Float_VALUE, 0, 0, 0, 0)));
            return true;
        }
        boolean zB3 = Intrinsics.b(lowerCase, "img");
        Drawable drawable = (Drawable) this.c;
        if (zB3) {
            f(z, output, new C5163k(drawable, i, new C5146b(attributes)));
            return true;
        }
        boolean z2 = false;
        if (Intrinsics.b(lowerCase, com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_VIDEO)) {
            if (z) {
                f(true, output, new r(context, drawable, i, new C5146b(attributes)));
                Intrinsics.checkNotNullParameter(attributes, "attributes");
                f(false, output, new r(context, drawable, i, new C5146b(attributes)));
                return true;
            }
        } else {
            if (!Intrinsics.b(lowerCase, "audio")) {
                if (Intrinsics.b(lowerCase, "p")) {
                    e(output, z, X2.b(i, alignmentRendering, new C5146b(attributes), new f(0)));
                    return true;
                }
                if (Intrinsics.b(lowerCase, "hr")) {
                    if (!z) {
                        b(output, C5162j.class);
                        return true;
                    }
                    Drawable drawableF = g.f(context, R.drawable.img_hr);
                    Intrinsics.d(drawableF);
                    h(output, new C5162j(drawableF, i, new C5146b(attributes), null));
                    output.append((char) 65279);
                    return true;
                }
                if (Intrinsics.b(lowerCase, "pre")) {
                    e(output, z, P2.a(i, alignmentRendering, new C5146b(attributes), new org.wordpress.aztec.formatting.g(0, DefinitionKt.NO_Float_VALUE, 0, 0, 0, 0, 0, 0, 0)));
                    return true;
                }
                if (Intrinsics.b(lowerCase, "input")) {
                    if (z && Intrinsics.b(attributes.getValue(DBUserFields.Names.USER_UPGRADE_TYPE), "checkbox")) {
                        Object objV2 = CollectionsKt.V(arrayList3);
                        C5164l c5164l = objV2 instanceof C5164l ? (C5164l) objV2 : null;
                        if (c5164l != null) {
                            String value = attributes.getValue("checked");
                            if (value != null && !value.equals("false")) {
                                z2 = true;
                            }
                            c5164l.b.d("checked", String.valueOf(z2));
                            return true;
                        }
                    }
                } else if (tag.length() == 2 && Character.toLowerCase(tag.charAt(0)) == 'h' && Intrinsics.g(tag.charAt(1), 49) >= 0 && Intrinsics.g(tag.charAt(1), 54) <= 0) {
                    e(output, z, M2.c(i, tag, new C5146b(attributes), alignmentRendering, new org.wordpress.aztec.formatting.c(0, V.c())));
                    return true;
                }
                return false;
            }
            if (z) {
                f(true, output, new C5153a(context, drawable, i, new C5146b(attributes)));
                Intrinsics.checkNotNullParameter(attributes, "attributes");
                f(false, output, new C5153a(context, drawable, i, new C5146b(attributes)));
            }
        }
        return true;
    }

    public void h(SpannableStringBuilder spannableStringBuilder, Object obj) {
        ((ArrayList) this.d).add(obj);
        spannableStringBuilder.setSpan(obj, spannableStringBuilder.length(), spannableStringBuilder.length(), 17);
    }

    public Aw i() throws GeneralSecurityException {
        C2883yp c2883yp;
        C2604sA c2604sAB;
        Hw hw = (Hw) this.a;
        if (hw == null) {
            throw new GeneralSecurityException("Cannot build without parameters");
        }
        C2883yp c2883yp2 = (C2883yp) this.b;
        if (c2883yp2 == null || (c2883yp = (C2883yp) this.c) == null) {
            throw new GeneralSecurityException("Cannot build without key material");
        }
        if (hw.a != ((C2604sA) c2883yp2.b).a.length) {
            throw new GeneralSecurityException("AES key size mismatch");
        }
        if (hw.b != ((C2604sA) c2883yp.b).a.length) {
            throw new GeneralSecurityException("HMAC key size mismatch");
        }
        if (hw.a() && ((Integer) this.d) == null) {
            throw new GeneralSecurityException("Cannot create key without ID requirement with parameters with ID requirement");
        }
        if (!((Hw) this.a).a() && ((Integer) this.d) != null) {
            throw new GeneralSecurityException("Cannot create key with ID requirement with parameters without ID requirement");
        }
        Gw gw = ((Hw) this.a).e;
        if (gw == Gw.e) {
            c2604sAB = Yx.a;
        } else if (gw == Gw.d) {
            c2604sAB = Yx.a(((Integer) this.d).intValue());
        } else {
            if (gw != Gw.c) {
                throw new IllegalStateException("Unknown AesCtrHmacAeadParameters.Variant: ".concat(String.valueOf(((Hw) this.a).e)));
            }
            c2604sAB = Yx.b(((Integer) this.d).intValue());
        }
        return new Aw((Hw) this.a, (C2883yp) this.b, (C2883yp) this.c, c2604sAB, (Integer) this.d);
    }

    public a(com.quizlet.infra.contracts.growthbook.a growthBook, String configurationName, Integer defaultValue) {
        Intrinsics.checkNotNullParameter(growthBook, "growthBook");
        Intrinsics.checkNotNullParameter(configurationName, "configurationName");
        Intrinsics.checkNotNullParameter(defaultValue, "defaultValue");
        this.a = growthBook;
        this.b = configurationName;
        this.c = defaultValue;
        this.d = l.b(new o(this, 29));
    }

    public a(com.google.firebase.crashlytics.internal.settings.b dataStoreFactory, com.quizlet.data.connectivity.a networkStatus, org.slf4j.b logger) {
        Intrinsics.checkNotNullParameter(dataStoreFactory, "dataStoreFactory");
        Intrinsics.checkNotNullParameter(networkStatus, "networkStatus");
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.a = dataStoreFactory;
        this.b = networkStatus;
        this.c = logger;
        this.d = new LinkedHashMap();
    }
}
