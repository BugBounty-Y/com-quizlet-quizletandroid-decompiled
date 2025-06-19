package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Shader;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.os.Looper;
import android.util.AttributeSet;
import android.util.Log;
import android.widget.EditText;
import android.widget.ImageView;
import androidx.collection.C0208f;
import androidx.compose.foundation.lazy.layout.AbstractC0448u;
import androidx.compose.foundation.lazy.layout.C0435g;
import androidx.compose.foundation.lazy.layout.InterfaceC0447t;
import androidx.paging.C1335q;
import com.comscore.streaming.EventType;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.Feature;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.ads.Ls;
import com.google.android.gms.internal.measurement.C3083y1;
import com.google.android.gms.internal.mlkit_vision_barcode.C3198l7;
import com.google.android.gms.internal.mlkit_vision_barcode.C3268u;
import com.google.android.gms.internal.mlkit_vision_barcode.C3306y5;
import com.google.android.gms.internal.mlkit_vision_barcode.N7;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3502n4;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.common.ads.C4634a;
import com.quizlet.uicommon.ui.common.views.StatefulTintImageView;
import com.quizlet.uicommon.ui.common.widgets.QFormField;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;
import kotlinx.serialization.descriptors.SerialDescriptor;

/* renamed from: androidx.appcompat.widget.z, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0122z implements androidx.compose.foundation.lazy.layout.P, io.reactivex.rxjava3.functions.b, com.quizlet.uicommon.ui.common.widgets.e {
    public final /* synthetic */ int a;
    public int b;
    public Object c;
    public Object d;

    public /* synthetic */ C0122z(int i, char c) {
        this.a = i;
    }

    /* JADX WARN: Code restructure failed: missing block: B:101:0x01e1, code lost:
    
        throw new org.xmlpull.v1.XmlPullParserException(r4.getPositionDescription() + ": <item> tag requires a 'color' attribute and a 'offset' attribute!");
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static androidx.appcompat.widget.C0122z k(android.content.res.Resources r29, int r30, android.content.res.Resources.Theme r31) {
        /*
            Method dump skipped, instructions count: 675
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.C0122z.k(android.content.res.Resources, int, android.content.res.Resources$Theme):androidx.appcompat.widget.z");
    }

    public void A(Bundle bundle) {
        this.b = 1;
        this.d = bundle;
        for (Map.Entry entry : ((Map) this.c).entrySet()) {
            ((com.google.android.gms.common.api.internal.l) entry.getValue()).b(bundle != null ? bundle.getBundle((String) entry.getKey()) : null);
        }
    }

    public byte[] B(int i) throws IOException {
        ((C3) this.d).i = Boolean.valueOf(1 == (i ^ 1));
        C3 c3 = (C3) this.d;
        c3.g = Boolean.FALSE;
        C3198l7 c3198l7 = new C3198l7(c3);
        androidx.camera.camera2.internal.c0 c0Var = (androidx.camera.camera2.internal.c0) this.c;
        c0Var.b = c3198l7;
        try {
            N7.b();
            N7 n7 = N7.c;
            if (i == 0) {
                C3306y5 c3306y5 = new C3306y5(c0Var);
                com.google.firebase.encoders.json.d dVar = new com.google.firebase.encoders.json.d();
                n7.a(dVar);
                dVar.d = true;
                StringWriter stringWriter = new StringWriter();
                try {
                    com.google.firebase.encoders.json.e eVar = new com.google.firebase.encoders.json.e(stringWriter, dVar.a, dVar.b, dVar.c, dVar.d);
                    eVar.h(c3306y5);
                    eVar.j();
                    eVar.b.flush();
                } catch (IOException unused) {
                }
                return stringWriter.toString().getBytes("utf-8");
            }
            C3306y5 c3306y52 = new C3306y5(c0Var);
            com.google.android.gms.internal.mlkit_vision_barcode.O o = new com.google.android.gms.internal.mlkit_vision_barcode.O();
            o.a = new HashMap();
            o.b = new HashMap();
            o.c = com.google.android.gms.internal.mlkit_vision_barcode.O.d;
            n7.a(o);
            HashMap map = new HashMap((HashMap) o.a);
            HashMap map2 = new HashMap((HashMap) o.b);
            com.google.android.gms.internal.mlkit_vision_barcode.M m = (com.google.android.gms.internal.mlkit_vision_barcode.M) o.c;
            com.google.android.gms.internal.mlkit_vision_barcode.O o2 = new com.google.android.gms.internal.mlkit_vision_barcode.O();
            o2.a = map;
            o2.b = map2;
            o2.c = m;
            return o2.a(c3306y52);
        } catch (UnsupportedEncodingException e) {
            throw new UnsupportedOperationException("Failed to covert logging to UTF-8 byte array", e);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:40:0x0089 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:49:0x000c A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void C(int r10, int r11, android.content.Intent r12) {
        /*
            r9 = this;
            java.lang.Object r0 = r9.c
            java.util.Map r0 = (java.util.Map) r0
            java.util.Collection r0 = r0.values()
            java.util.Iterator r0 = r0.iterator()
        Lc:
            boolean r1 = r0.hasNext()
            if (r1 == 0) goto L95
            java.lang.Object r1 = r0.next()
            com.google.android.gms.common.api.internal.l r1 = (com.google.android.gms.common.api.internal.l) r1
            java.util.concurrent.atomic.AtomicReference r2 = r1.c
            java.lang.Object r2 = r2.get()
            com.google.android.gms.common.api.internal.D r2 = (com.google.android.gms.common.api.internal.D) r2
            r3 = 3
            r4 = 0
            com.google.android.gms.common.api.internal.e r5 = r1.g
            java.util.concurrent.atomic.AtomicReference r6 = r1.c
            r7 = 1
            if (r10 == r7) goto L55
            r7 = 2
            if (r10 == r7) goto L2d
            goto L87
        L2d:
            android.app.Activity r7 = r1.a()
            int r8 = com.google.android.gms.common.c.a
            com.google.android.gms.common.GoogleApiAvailability r1 = r1.e
            int r1 = r1.c(r7, r8)
            if (r1 != 0) goto L48
            r6.set(r4)
            com.google.android.gms.internal.ads.Ls r1 = r5.n
            android.os.Message r2 = r1.obtainMessage(r3)
            r1.sendMessage(r2)
            goto Lc
        L48:
            if (r2 == 0) goto Lc
            com.google.android.gms.common.ConnectionResult r3 = r2.b
            int r3 = r3.b
            r7 = 18
            if (r3 != r7) goto L87
            if (r1 != r7) goto L87
            goto Lc
        L55:
            r1 = -1
            if (r11 != r1) goto L65
            r6.set(r4)
            com.google.android.gms.internal.ads.Ls r1 = r5.n
            android.os.Message r2 = r1.obtainMessage(r3)
            r1.sendMessage(r2)
            goto Lc
        L65:
            if (r11 != 0) goto L87
            if (r2 == 0) goto Lc
            r1 = 13
            if (r12 == 0) goto L73
            java.lang.String r3 = "<<ResolutionFailureErrorDetail>>"
            int r1 = r12.getIntExtra(r3, r1)
        L73:
            com.google.android.gms.common.ConnectionResult r3 = new com.google.android.gms.common.ConnectionResult
            com.google.android.gms.common.ConnectionResult r8 = r2.b
            java.lang.String r8 = r8.toString()
            r3.<init>(r7, r1, r4, r8)
            r6.set(r4)
            int r1 = r2.a
            r5.h(r3, r1)
            goto Lc
        L87:
            if (r2 == 0) goto Lc
            r6.set(r4)
            com.google.android.gms.common.ConnectionResult r1 = r2.b
            int r2 = r2.a
            r5.h(r1, r2)
            goto Lc
        L95:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.C0122z.C(int, int, android.content.Intent):void");
    }

    public void D(Bundle bundle) {
        if (bundle == null) {
            return;
        }
        for (Map.Entry entry : ((Map) this.c).entrySet()) {
            Bundle bundle2 = new Bundle();
            com.google.android.gms.common.api.internal.D d = (com.google.android.gms.common.api.internal.D) ((com.google.android.gms.common.api.internal.l) entry.getValue()).c.get();
            if (d != null) {
                bundle2.putBoolean("resolving_error", true);
                bundle2.putInt("failed_client_id", d.a);
                ConnectionResult connectionResult = d.b;
                bundle2.putInt("failed_status", connectionResult.b);
                bundle2.putParcelable("failed_resolution", connectionResult.c);
            }
            bundle.putBundle((String) entry.getKey(), bundle2);
        }
    }

    @Override // androidx.compose.foundation.lazy.layout.P
    public int a(Object obj) {
        androidx.collection.C c = (androidx.collection.C) this.c;
        int iC = c.c(obj);
        if (iC >= 0) {
            return c.c[iC];
        }
        return -1;
    }

    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object obj, Object obj2) {
        Boolean isEligibleForAds = (Boolean) obj;
        Boolean needsChildDirectedTreatment = (Boolean) obj2;
        Intrinsics.checkNotNullParameter(isEligibleForAds, "isEligibleForAds");
        Intrinsics.checkNotNullParameter(needsChildDirectedTreatment, "needsChildDirectedTreatment");
        com.quizlet.ads.c.b.getClass();
        return new C4634a(com.google.mlkit.common.sdkinternal.model.a.r(this.b), (String) this.c, isEligibleForAds.booleanValue(), needsChildDirectedTreatment.booleanValue(), ((com.quizlet.remote.connectivity.b) ((com.quizlet.data.connectivity.a) ((com.quizlet.data.repository.course.membership.c) this.d).c)).a().a);
    }

    public void b(Object obj) {
        int i = this.b;
        if (i == 4) {
            Object[] objArr = new Object[5];
            ((Object[]) this.d)[4] = objArr;
            this.d = objArr;
            i = 0;
        }
        ((Object[]) this.d)[i] = obj;
        this.b = i + 1;
    }

    public void c(int i, InterfaceC0447t interfaceC0447t) {
        if (i < 0) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "size should be >=0, but was ").toString());
        }
        if (i == 0) {
            return;
        }
        C0435g c0435g = new C0435g(this.b, i, interfaceC0447t);
        this.b += i;
        ((androidx.compose.runtime.collection.b) this.c).b(c0435g);
    }

    public void d() {
        o1 o1Var;
        ImageView imageView = (ImageView) this.c;
        Drawable drawable = imageView.getDrawable();
        if (drawable != null) {
            AbstractC0102o0.a(drawable);
        }
        if (drawable == null || (o1Var = (o1) this.d) == null) {
            return;
        }
        C0112u.e(drawable, o1Var, imageView.getDrawableState());
    }

    public com.google.firebase.installations.remote.b e() {
        if (!"".isEmpty()) {
            throw new IllegalStateException("Missing required properties:".concat(""));
        }
        String str = (String) this.c;
        return new com.google.firebase.installations.remote.b(this.b, ((Long) this.d).longValue(), str);
    }

    @Override // com.quizlet.uicommon.ui.common.widgets.e
    public boolean f(QFormField formField) {
        Intrinsics.checkNotNullParameter(formField, "formField");
        EditText editText = formField.getEditText();
        EditText editText2 = (EditText) this.c;
        return Intrinsics.b(editText2, editText) && org.apache.commons.lang3.e.d(editText2.getText());
    }

    @Override // com.quizlet.uicommon.ui.common.widgets.e
    public CharSequence g(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        String string = context.getString(this.b);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        return string;
    }

    public com.google.common.collect.C h() {
        com.google.common.collect.k kVar = (com.google.common.collect.k) this.d;
        if (kVar != null) {
            throw kVar.a();
        }
        com.google.common.collect.C cD = com.google.common.collect.C.d(this.b, (Object[]) this.c, this);
        com.google.common.collect.k kVar2 = (com.google.common.collect.k) this.d;
        if (kVar2 == null) {
            return cD;
        }
        throw kVar2.a();
    }

    public void i(int i) {
        if (i < 0 || i >= this.b) {
            StringBuilder sbV = android.support.v4.media.session.a.v(i, "Index ", ", size ");
            sbV.append(this.b);
            throw new IndexOutOfBoundsException(sbV.toString());
        }
    }

    @Override // com.quizlet.uicommon.ui.common.widgets.e
    public void j(QFormField formField) {
        Intrinsics.checkNotNullParameter(formField, "formField");
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [java.lang.Object, java.util.List] */
    public void l(androidx.compose.ui.input.pointer.f fVar) {
        ?? r0 = fVar.a;
        int size = r0.size();
        int i = 0;
        while (true) {
            androidx.compose.ui.input.pointer.r rVar = (androidx.compose.ui.input.pointer.r) this.d;
            if (i >= size) {
                androidx.compose.ui.layout.r rVar2 = (androidx.compose.ui.layout.r) this.c;
                if (rVar2 == null) {
                    throw new IllegalStateException("layoutCoordinates not set");
                }
                androidx.compose.ui.input.pointer.l.h(fVar, rVar2.U(0L), new androidx.compose.foundation.text.selection.n0(18, this, rVar), false);
                if (this.b == 2) {
                    int size2 = r0.size();
                    for (int i2 = 0; i2 < size2; i2++) {
                        ((androidx.compose.ui.input.pointer.n) r0.get(i2)).a();
                    }
                    C3083y1 c3083y1 = fVar.b;
                    if (c3083y1 == null) {
                        return;
                    }
                    c3083y1.b = !rVar.d;
                    return;
                }
                return;
            }
            if (((androidx.compose.ui.input.pointer.n) r0.get(i)).b()) {
                if (this.b == 2) {
                    androidx.compose.ui.layout.r rVar3 = (androidx.compose.ui.layout.r) this.c;
                    if (rVar3 == null) {
                        throw new IllegalStateException("layoutCoordinates not set");
                    }
                    androidx.compose.ui.input.pointer.l.h(fVar, rVar3.U(0L), new androidx.compose.ui.input.pointer.q(rVar, 0), true);
                }
                this.b = 3;
                return;
            }
            i++;
        }
    }

    @Override // com.quizlet.uicommon.ui.common.widgets.e
    public void m(QFormField formField, StatefulTintImageView view) {
        Intrinsics.checkNotNullParameter(formField, "formField");
        Intrinsics.checkNotNullParameter(view, "view");
        ((Function0) this.d).invoke();
    }

    @Override // com.quizlet.uicommon.ui.common.widgets.e
    public int n() {
        return R.drawable.ic_sys_close_x;
    }

    public C0435g o(int i) {
        i(i);
        C0435g c0435g = (C0435g) this.d;
        if (c0435g != null) {
            int i2 = c0435g.b;
            int i3 = c0435g.a;
            if (i < i2 + i3 && i3 <= i) {
                return c0435g;
            }
        }
        androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) this.c;
        C0435g c0435g2 = (C0435g) bVar.a[AbstractC0448u.e(i, bVar)];
        this.d = c0435g2;
        return c0435g2;
    }

    public Object p(int i) {
        int i2 = i - this.b;
        if (i2 < 0) {
            return null;
        }
        Object[] objArr = (Object[]) this.d;
        if (i2 <= C4933y.E(objArr)) {
            return objArr[i2];
        }
        return null;
    }

    public String q() {
        StringBuilder sb = new StringBuilder("$");
        int i = this.b + 1;
        for (int i2 = 0; i2 < i; i2++) {
            Object obj = ((Object[]) this.c)[i2];
            if (obj instanceof SerialDescriptor) {
                SerialDescriptor serialDescriptor = (SerialDescriptor) obj;
                if (!Intrinsics.b(serialDescriptor.e(), kotlinx.serialization.descriptors.j.c)) {
                    int i3 = ((int[]) this.d)[i2];
                    if (i3 >= 0) {
                        sb.append(".");
                        sb.append(serialDescriptor.g(i3));
                    }
                } else if (((int[]) this.d)[i2] != -1) {
                    sb.append("[");
                    sb.append(((int[]) this.d)[i2]);
                    sb.append("]");
                }
            } else if (obj != kotlinx.serialization.json.internal.l.a) {
                sb.append("['");
                sb.append(obj);
                sb.append("']");
            }
        }
        return sb.toString();
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.io.Serializable r(kotlin.coroutines.jvm.internal.c r9) {
        /*
            r8 = this;
            boolean r0 = r9 instanceof androidx.paging.C1331o
            if (r0 == 0) goto L13
            r0 = r9
            androidx.paging.o r0 = (androidx.paging.C1331o) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            androidx.paging.o r0 = new androidx.paging.o
            r0.<init>(r8, r9)
        L18:
            java.lang.Object r9 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            kotlinx.coroutines.sync.c r1 = r0.k
            androidx.appcompat.widget.z r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L49
        L2b:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            r0.j = r8
            java.lang.Object r9 = r8.d
            kotlinx.coroutines.sync.c r9 = (kotlinx.coroutines.sync.c) r9
            r0.k = r9
            r0.n = r3
            java.lang.Object r0 = r9.d(r0)
            if (r0 != r1) goto L47
            return r1
        L47:
            r0 = r8
            r1 = r9
        L49:
            r9 = 0
            java.lang.Object r2 = r0.c     // Catch: java.lang.Throwable -> L85
            androidx.paging.q r2 = (androidx.paging.C1335q) r2     // Catch: java.lang.Throwable -> L85
            java.util.List r2 = r2.b()     // Catch: java.lang.Throwable -> L85
            int r0 = r0.b     // Catch: java.lang.Throwable -> L85
            int r4 = r2.size()     // Catch: java.lang.Throwable -> L85
            int r0 = r0 - r4
            int r0 = r0 + r3
            java.util.ArrayList r3 = new java.util.ArrayList     // Catch: java.lang.Throwable -> L85
            r4 = 10
            int r4 = kotlin.collections.C.q(r2, r4)     // Catch: java.lang.Throwable -> L85
            r3.<init>(r4)     // Catch: java.lang.Throwable -> L85
            java.util.Iterator r2 = r2.iterator()     // Catch: java.lang.Throwable -> L85
            r4 = 0
        L6a:
            boolean r5 = r2.hasNext()     // Catch: java.lang.Throwable -> L85
            if (r5 == 0) goto L8b
            java.lang.Object r5 = r2.next()     // Catch: java.lang.Throwable -> L85
            int r6 = r4 + 1
            if (r4 < 0) goto L87
            androidx.paging.N r5 = (androidx.paging.N) r5     // Catch: java.lang.Throwable -> L85
            kotlin.collections.IndexedValue r7 = new kotlin.collections.IndexedValue     // Catch: java.lang.Throwable -> L85
            int r4 = r4 + r0
            r7.<init>(r4, r5)     // Catch: java.lang.Throwable -> L85
            r3.add(r7)     // Catch: java.lang.Throwable -> L85
            r4 = r6
            goto L6a
        L85:
            r0 = move-exception
            goto L8f
        L87:
            kotlin.collections.B.p()     // Catch: java.lang.Throwable -> L85
            throw r9     // Catch: java.lang.Throwable -> L85
        L8b:
            r1.f(r9)
            return r3
        L8f:
            r1.f(r9)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.C0122z.r(kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    public boolean s() {
        ColorStateList colorStateList;
        return ((Shader) this.c) == null && (colorStateList = (ColorStateList) this.d) != null && colorStateList.isStateful();
    }

    public void t(AttributeSet attributeSet, int i) {
        int resourceId;
        ImageView imageView = (ImageView) this.c;
        Context context = imageView.getContext();
        int[] iArr = androidx.appcompat.a.f;
        com.quizlet.data.repository.classfolder.e eVarM = com.quizlet.data.repository.classfolder.e.m(context, attributeSet, iArr, i);
        androidx.core.view.V.n(imageView, imageView.getContext(), iArr, attributeSet, (TypedArray) eVarM.c, i);
        try {
            Drawable drawable = imageView.getDrawable();
            TypedArray typedArray = (TypedArray) eVarM.c;
            if (drawable == null && (resourceId = typedArray.getResourceId(1, -1)) != -1 && (drawable = com.facebook.appevents.g.f(imageView.getContext(), resourceId)) != null) {
                imageView.setImageDrawable(drawable);
            }
            if (drawable != null) {
                AbstractC0102o0.a(drawable);
            }
            if (typedArray.hasValue(2)) {
                imageView.setImageTintList(eVarM.e(2));
            }
            if (typedArray.hasValue(3)) {
                imageView.setImageTintMode(AbstractC0102o0.c(typedArray.getInt(3, -1), null));
            }
            eVarM.n();
        } catch (Throwable th) {
            eVarM.n();
            throw th;
        }
    }

    public String toString() {
        switch (this.a) {
            case EventType.WINDOW_STATE /* 22 */:
                return q();
            case EventType.AUDIO /* 23 */:
                StringBuilder sb = new StringBuilder();
                if (((okhttp3.B) this.c) == okhttp3.B.HTTP_1_0) {
                    sb.append("HTTP/1.0");
                } else {
                    sb.append("HTTP/1.1");
                }
                sb.append(' ');
                sb.append(this.b);
                sb.append(' ');
                sb.append((String) this.d);
                String string = sb.toString();
                Intrinsics.checkNotNullExpressionValue(string, "StringBuilder().apply(builderAction).toString()");
                return string;
            default:
                return super.toString();
        }
    }

    public void u(Object obj, Object obj2) {
        int i = (this.b + 1) * 2;
        Object[] objArr = (Object[]) this.c;
        if (i > objArr.length) {
            this.c = Arrays.copyOf(objArr, C3268u.d(objArr.length, i));
        }
        AbstractC3502n4.h(obj, obj2);
        Object[] objArr2 = (Object[]) this.c;
        int i2 = this.b;
        int i3 = i2 * 2;
        objArr2[i3] = obj;
        objArr2[i3 + 1] = obj2;
        this.b = i2 + 1;
    }

    public void v(Collection collection) {
        if (collection instanceof Collection) {
            int size = (collection.size() + this.b) * 2;
            Object[] objArr = (Object[]) this.c;
            if (size > objArr.length) {
                this.c = Arrays.copyOf(objArr, C3268u.d(objArr.length, size));
            }
        }
        Iterator it2 = collection.iterator();
        while (it2.hasNext()) {
            Map.Entry entry = (Map.Entry) it2.next();
            u(entry.getKey(), entry.getValue());
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object w(kotlin.collections.IndexedValue r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof androidx.paging.C1333p
            if (r0 == 0) goto L13
            r0 = r6
            androidx.paging.p r0 = (androidx.paging.C1333p) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            androidx.paging.p r0 = new androidx.paging.p
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 1
            if (r2 == 0) goto L37
            if (r2 != r3) goto L2f
            kotlinx.coroutines.sync.c r5 = r0.l
            kotlin.collections.IndexedValue r1 = r0.k
            androidx.appcompat.widget.z r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r6 = r5
            r5 = r1
            goto L4e
        L2f:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L37:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r4
            r0.k = r5
            java.lang.Object r6 = r4.d
            kotlinx.coroutines.sync.c r6 = (kotlinx.coroutines.sync.c) r6
            r0.l = r6
            r0.o = r3
            java.lang.Object r0 = r6.d(r0)
            if (r0 != r1) goto L4d
            return r1
        L4d:
            r0 = r4
        L4e:
            r1 = 0
            int r2 = r5.a     // Catch: java.lang.Throwable -> L66
            r0.b = r2     // Catch: java.lang.Throwable -> L66
            java.lang.Object r0 = r0.c     // Catch: java.lang.Throwable -> L66
            androidx.paging.q r0 = (androidx.paging.C1335q) r0     // Catch: java.lang.Throwable -> L66
            java.lang.Object r5 = r5.b     // Catch: java.lang.Throwable -> L66
            androidx.paging.N r5 = (androidx.paging.N) r5     // Catch: java.lang.Throwable -> L66
            r0.a(r5)     // Catch: java.lang.Throwable -> L66
            kotlin.Unit r5 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L66
            r6.f(r1)
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        L66:
            r5 = move-exception
            r6.f(r1)
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.C0122z.w(kotlin.collections.IndexedValue, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public void x(int i) {
        ImageView imageView = (ImageView) this.c;
        if (i != 0) {
            Drawable drawableF = com.facebook.appevents.g.f(imageView.getContext(), i);
            if (drawableF != null) {
                AbstractC0102o0.a(drawableF);
            }
            imageView.setImageDrawable(drawableF);
        } else {
            imageView.setImageDrawable(null);
        }
        d();
    }

    public void y(String str, Feature feature) {
        int i = this.b + 1;
        Object[] objArr = (Object[]) this.c;
        int length = objArr.length;
        int i2 = i + i;
        if (i2 > length) {
            if (i2 < 0) {
                throw new AssertionError("cannot store more than MAX_VALUE elements");
            }
            int i3 = length + (length >> 1) + 1;
            if (i3 < i2) {
                int iHighestOneBit = Integer.highestOneBit(i2 - 1);
                i3 = iHighestOneBit + iHighestOneBit;
            }
            if (i3 < 0) {
                i3 = SubsamplingScaleImageView.TILE_SIZE_AUTO;
            }
            this.c = Arrays.copyOf(objArr, i3);
        }
        Object[] objArr2 = (Object[]) this.c;
        int i4 = this.b;
        int i5 = i4 + i4;
        objArr2[i5] = str;
        objArr2[i5 + 1] = feature;
        this.b = i4 + 1;
    }

    public void z(com.google.android.gms.common.api.internal.l lVar) {
        Map map = (Map) this.c;
        if (map.containsKey("ConnectionlessLifecycleHelper")) {
            StringBuilder sb = new StringBuilder("ConnectionlessLifecycleHelper".length() + 59);
            sb.append("LifecycleCallback with tag ConnectionlessLifecycleHelper already added to this fragment.");
            throw new IllegalArgumentException(sb.toString());
        }
        map.put("ConnectionlessLifecycleHelper", lVar);
        if (this.b > 0) {
            new Ls(Looper.getMainLooper(), 3).post(new androidx.camera.core.impl.utils.futures.h(this, false, lVar, 23));
        }
    }

    public C0122z(int i, String str, com.quizlet.data.repository.course.membership.c cVar) {
        this.a = 19;
        this.b = i;
        this.c = str;
        this.d = cVar;
    }

    public C0122z(int i, String str, ArrayList arrayList) {
        this.a = 9;
        this.b = i;
        this.d = str;
        this.c = arrayList;
    }

    public /* synthetic */ C0122z(Object obj, Object obj2, int i, int i2) {
        this.a = i2;
        this.c = obj;
        this.d = obj2;
        this.b = i;
    }

    public C0122z(androidx.camera.camera2.internal.c0 c0Var, int i) {
        this.a = 14;
        this.d = new C3();
        this.c = c0Var;
        N7.b();
        this.b = i;
    }

    public C0122z(String str, String[] strArr) {
        String string;
        this.a = 12;
        if (strArr.length == 0) {
            string = "";
        } else {
            StringBuilder sb = new StringBuilder();
            sb.append('[');
            for (String str2 : strArr) {
                if (sb.length() > 1) {
                    sb.append(",");
                }
                sb.append(str2);
            }
            sb.append("] ");
            string = sb.toString();
        }
        this.d = string;
        this.c = str;
        int length = str.length();
        Object[] objArr = {str, 23};
        if (length <= 23) {
            int i = 2;
            while (i <= 7 && !Log.isLoggable((String) this.c, i)) {
                i++;
            }
            this.b = i;
            return;
        }
        throw new IllegalArgumentException(String.format("tag \"%s\" is longer than the %d character maximum", objArr));
    }

    public C0122z(EditText focusedField, int i, Function0 onClearIconClicked) {
        this.a = 20;
        Intrinsics.checkNotNullParameter(focusedField, "focusedField");
        Intrinsics.checkNotNullParameter(onClearIconClicked, "onClearIconClicked");
        this.c = focusedField;
        this.b = i;
        this.d = onClearIconClicked;
    }

    public C0122z(okhttp3.B protocol, int i, String message) {
        this.a = 23;
        Intrinsics.checkNotNullParameter(protocol, "protocol");
        Intrinsics.checkNotNullParameter(message, "message");
        this.c = protocol;
        this.b = i;
        this.d = message;
    }

    public C0122z(androidx.compose.ui.input.pointer.r rVar) {
        this.a = 5;
        this.d = rVar;
        this.b = 1;
    }

    public C0122z(ImageView imageView) {
        this.a = 0;
        this.b = 0;
        this.c = imageView;
    }

    public C0122z(IntRange intRange, AbstractC0448u abstractC0448u) {
        this.a = 2;
        C0122z c0122zJ = abstractC0448u.j();
        int i = intRange.a;
        if (i >= 0) {
            int iMin = Math.min(intRange.b, c0122zJ.b - 1);
            if (iMin < i) {
                androidx.collection.C c = androidx.collection.O.a;
                Intrinsics.e(c, "null cannot be cast to non-null type androidx.collection.ObjectIntMap<K of androidx.collection.ObjectIntMapKt.emptyObjectIntMap>");
                this.c = c;
                this.d = new Object[0];
                this.b = 0;
                return;
            }
            int i2 = (iMin - i) + 1;
            this.d = new Object[i2];
            this.b = i;
            androidx.collection.C c2 = new androidx.collection.C(i2);
            androidx.compose.foundation.lazy.layout.m0 m0Var = new androidx.compose.foundation.lazy.layout.m0(i, iMin, c2, this);
            c0122zJ.i(i);
            c0122zJ.i(iMin);
            if (iMin >= i) {
                androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) c0122zJ.c;
                int iE = AbstractC0448u.e(i, bVar);
                int i3 = ((C0435g) bVar.a[iE]).a;
                while (i3 <= iMin) {
                    C0435g c0435g = (C0435g) bVar.a[iE];
                    m0Var.invoke(c0435g);
                    i3 += c0435g.b;
                    iE++;
                }
                this.c = c2;
                return;
            }
            throw new IllegalArgumentException(("toIndex (" + iMin + ") should be not smaller than fromIndex (" + i + ')').toString());
        }
        throw new IllegalStateException("negative nearestRange.first");
    }

    public C0122z(int i, byte b) {
        this.a = i;
        switch (i) {
            case 7:
                this.c = new C1335q();
                this.d = kotlinx.coroutines.sync.d.a();
                this.b = -1;
                break;
            case 11:
                this.c = Collections.synchronizedMap(new C0208f(0));
                this.b = 0;
                break;
            case 13:
                this.c = new Object[8];
                this.b = 0;
                break;
            case 21:
                Object[] objArr = new Object[5];
                this.c = objArr;
                this.d = objArr;
                break;
            default:
                this.c = new androidx.compose.runtime.collection.b(new C0435g[16]);
                break;
        }
    }

    public C0122z(androidx.compose.ui.platform.Y0 y0) {
        this.a = 3;
        this.c = y0;
    }

    public C0122z(int i) {
        this.a = 16;
        this.c = new Object[i * 2];
        this.b = 0;
    }

    public C0122z(com.bumptech.glide.load.engine.k kVar) {
        this.a = 10;
        this.d = com.bumptech.glide.util.pool.d.a(150, new androidx.appcompat.app.Q(this));
        this.c = kVar;
    }
}
