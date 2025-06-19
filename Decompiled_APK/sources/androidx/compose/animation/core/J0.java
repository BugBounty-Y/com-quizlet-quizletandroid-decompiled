package androidx.compose.animation.core;

import android.content.Context;
import android.text.Editable;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.ads.AbstractC2270kd;
import com.google.android.gms.internal.mlkit_vision_barcode.Z4;
import com.google.android.gms.measurement.internal.InterfaceC3873i0;
import com.quizlet.quizletandroid.R;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.AztecText;

/* loaded from: classes.dex */
public abstract class J0 implements com.airbnb.lottie.model.animatable.f, InterfaceC3873i0, io.ktor.util.m {
    public final /* synthetic */ int a;
    public Object b;

    public J0(com.google.android.gms.measurement.internal.Y y) {
        this.a = 6;
        com.google.android.gms.common.internal.u.h(y);
        this.b = y;
    }

    public static androidx.compose.ui.graphics.painter.b G(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1059847108);
        androidx.compose.ui.graphics.painter.b bVarA = Z4.a(R.drawable.ic_brand_streak, c0814p, 0);
        c0814p.p(false);
        return bVarA;
    }

    public static androidx.compose.ui.graphics.painter.b H(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1396511592);
        androidx.compose.ui.graphics.painter.b bVarA = Z4.a(2131231326, c0814p, 0);
        c0814p.p(false);
        return bVarA;
    }

    public static androidx.compose.ui.graphics.painter.b v(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-153376330);
        androidx.compose.ui.graphics.painter.b bVarA = Z4.a(R.drawable.ic_brand_flashcard_sets, c0814p, 0);
        c0814p.p(false);
        return bVarA;
    }

    public static androidx.compose.ui.graphics.painter.b w(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(408508188);
        androidx.compose.ui.graphics.painter.b bVarA = Z4.a(R.drawable.ic_brand_generic_error, c0814p, 0);
        c0814p.p(false);
        return bVarA;
    }

    public androidx.compose.ui.graphics.painter.b A(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1493858660);
        androidx.compose.ui.graphics.painter.b bVarA = Z4.a(2131231307, c0814p, 0);
        c0814p.p(false);
        return bVarA;
    }

    public abstract com.quizlet.features.questiontypes.fitb.ui.e B();

    public androidx.compose.ui.graphics.painter.b C(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1848796164);
        androidx.compose.ui.graphics.painter.b bVarA = Z4.a(R.drawable.ic_brand_scan_document, c0814p, 0);
        c0814p.p(false);
        return bVarA;
    }

    public androidx.compose.ui.graphics.painter.b D(C0814p c0814p) {
        c0814p.X(-1532565488);
        androidx.compose.ui.graphics.painter.b bVarA = Z4.a(R.drawable.ic_brand_science_light, c0814p, 0);
        c0814p.p(false);
        return bVarA;
    }

    public com.quizlet.features.questiontypes.fitb.ui.e E() {
        return null;
    }

    public androidx.compose.ui.graphics.painter.b F(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1542218178);
        androidx.compose.ui.graphics.painter.b bVarA = Z4.a(R.drawable.ic_brand_select_words, c0814p, 0);
        c0814p.p(false);
        return bVarA;
    }

    public abstract Object I();

    public void J(com.bumptech.glide.load.engine.bitmap_recycle.g gVar) {
        ArrayDeque arrayDeque = (ArrayDeque) this.b;
        if (arrayDeque.size() < 20) {
            arrayDeque.offer(gVar);
        }
    }

    public void K(app.cash.sqldelight.driver.android.e transaction, app.cash.sqldelight.driver.android.e eVar, Throwable th, Object obj) throws Throwable {
        Intrinsics.checkNotNullParameter(transaction, "transaction");
        if (eVar != null) {
            eVar.g = transaction.f && transaction.g;
            eVar.b.addAll(transaction.b);
            eVar.c.addAll(transaction.c);
            eVar.d.addAll(transaction.d);
            eVar.e.addAll(transaction.e);
        } else if (transaction.f && transaction.g) {
            if (!transaction.e.isEmpty()) {
                app.cash.sqldelight.driver.android.i iVar = (app.cash.sqldelight.driver.android.i) this.b;
                String[] strArr = (String[]) transaction.e.toArray(new String[0]);
                String[] queryKeys = (String[]) Arrays.copyOf(strArr, strArr.length);
                Intrinsics.checkNotNullParameter(queryKeys, "queryKeys");
                LinkedHashSet linkedHashSet = new LinkedHashSet();
                synchronized (iVar.e) {
                    try {
                        for (String str : queryKeys) {
                            Set set = (Set) iVar.e.get(str);
                            if (set != null) {
                                linkedHashSet.addAll(set);
                            }
                        }
                        Unit unit = Unit.a;
                    } catch (Throwable th2) {
                        throw th2;
                    }
                }
                Iterator it2 = linkedHashSet.iterator();
                if (it2.hasNext()) {
                    throw android.support.v4.media.session.a.d(it2);
                }
            }
            transaction.e.clear();
            transaction.d.clear();
            Iterator it3 = transaction.b.iterator();
            while (it3.hasNext()) {
                ((Function0) it3.next()).invoke();
            }
            transaction.b.clear();
        } else {
            try {
                Iterator it4 = transaction.c.iterator();
                while (it4.hasNext()) {
                    ((Function0) it4.next()).invoke();
                }
                transaction.c.clear();
            } catch (Throwable th3) {
                if (th == null) {
                    throw th3;
                }
                throw new Throwable("Exception while rolling back from an exception.\nOriginal exception: " + th + "\nwith cause " + th.getCause() + "\n\nRollback exception: " + th3, th3);
            }
        }
        if (th != null) {
            throw th;
        }
    }

    public abstract void L(Object obj);

    public abstract void M(E0 e0);

    public abstract void N();

    public void O(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
    }

    public void P(String value) {
        Intrinsics.checkNotNullParameter(value, "value");
    }

    public abstract void Q();

    public com.google.common.util.concurrent.e R() {
        return AbstractC2270kd.a.a((androidx.appcompat.app.J) this.b);
    }

    public void S() {
        com.google.android.gms.measurement.internal.X x = ((com.google.android.gms.measurement.internal.Y) this.b).j;
        com.google.android.gms.measurement.internal.Y.k(x);
        x.S();
    }

    @Override // io.ktor.util.m
    public Set a() {
        Set setEntrySet = ((Map) this.b).entrySet();
        Intrinsics.checkNotNullParameter(setEntrySet, "<this>");
        Set setUnmodifiableSet = Collections.unmodifiableSet(setEntrySet);
        Intrinsics.checkNotNullExpressionValue(setUnmodifiableSet, "unmodifiableSet(...)");
        return setUnmodifiableSet;
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3873i0
    public com.google.android.material.shape.e b() {
        throw null;
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3873i0
    public com.google.android.gms.measurement.internal.I c() {
        throw null;
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3873i0
    public Context d() {
        throw null;
    }

    @Override // io.ktor.util.m
    public void e(String name, List values) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(values, "values");
        List listO = o(name);
        Iterator it2 = values.iterator();
        while (it2.hasNext()) {
            P((String) it2.next());
        }
        kotlin.collections.G.u(listO, values);
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3873i0
    public com.google.android.gms.common.util.a f() {
        throw null;
    }

    @Override // io.ktor.util.m
    public List h(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        return (List) ((Map) this.b).get(name);
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3873i0
    public com.google.android.gms.measurement.internal.X i() {
        throw null;
    }

    @Override // com.airbnb.lottie.model.animatable.f
    public List k() {
        return (List) this.b;
    }

    @Override // com.airbnb.lottie.model.animatable.f
    public boolean l() {
        List list = (List) this.b;
        return list.isEmpty() || (list.size() == 1 && ((com.airbnb.lottie.value.a) list.get(0)).c());
    }

    public void m(String name, String value) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(value, "value");
        P(value);
        o(name).add(value);
    }

    public abstract Object n(Object obj);

    @Override // io.ktor.util.m
    public Set names() {
        return ((Map) this.b).keySet();
    }

    public List o(String str) {
        Map map = (Map) this.b;
        List list = (List) map.get(str);
        if (list != null) {
            return list;
        }
        ArrayList arrayList = new ArrayList();
        O(str);
        map.put(str, arrayList);
        return arrayList;
    }

    public Object p(Object obj) {
        synchronized (((HashMap) this.b)) {
            try {
                if (((HashMap) this.b).containsKey(obj)) {
                    return ((HashMap) this.b).get(obj);
                }
                Object objN = n(obj);
                ((HashMap) this.b).put(obj, objN);
                return objN;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public String q(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        List listH = h(name);
        if (listH != null) {
            return (String) CollectionsKt.firstOrNull(listH);
        }
        return null;
    }

    public androidx.compose.ui.graphics.painter.b r(C0814p c0814p) {
        c0814p.X(-42552948);
        androidx.compose.ui.graphics.painter.b bVarA = Z4.a(R.drawable.ic_brand_arts_and_humanities_light, c0814p, 0);
        c0814p.p(false);
        return bVarA;
    }

    public androidx.compose.ui.graphics.painter.b s(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1856008678);
        androidx.compose.ui.graphics.painter.b bVarA = Z4.a(R.drawable.ic_brand_creation_toolkit, c0814p, 0);
        c0814p.p(false);
        return bVarA;
    }

    public abstract Object t();

    public String toString() {
        switch (this.a) {
            case 3:
                StringBuilder sb = new StringBuilder();
                List list = (List) this.b;
                if (!list.isEmpty()) {
                    sb.append("values=");
                    sb.append(Arrays.toString(list.toArray()));
                }
                return sb.toString();
            default:
                return super.toString();
        }
    }

    public Editable u() {
        Editable editableText = ((AztecText) this.b).getEditableText();
        Intrinsics.checkNotNullExpressionValue(editableText, "getEditableText(...)");
        return editableText;
    }

    public com.quizlet.features.questiontypes.data.a x() {
        return (com.quizlet.features.questiontypes.data.a) this.b;
    }

    public androidx.compose.ui.graphics.painter.b y(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(421068476);
        androidx.compose.ui.graphics.painter.b bVarA = Z4.a(R.drawable.ic_brand_locked, c0814p, 0);
        c0814p.p(false);
        return bVarA;
    }

    public abstract String z();

    public J0(com.quizlet.shared.quizletapi.base.e service) {
        this.a = 10;
        Intrinsics.checkNotNullParameter(service, "service");
        this.b = service;
    }

    public J0(AztecText editor) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(editor, "editor");
        this.b = editor;
    }

    public J0(com.quizlet.quizletandroid.ui.activitycenter.views.i meteringDataStore) {
        this.a = 14;
        Intrinsics.checkNotNullParameter(meteringDataStore, "meteringDataStore");
        this.b = meteringDataStore;
    }

    public J0(com.snowplowanalytics.core.tracker.k serviceProvider) {
        this.a = 12;
        Intrinsics.checkNotNullParameter(serviceProvider, "serviceProvider");
        this.b = serviceProvider;
    }

    public J0(List list) {
        this.a = 3;
        this.b = list;
    }

    public J0(int i) {
        this.a = i;
        switch (i) {
            case 4:
                char[] cArr = com.bumptech.glide.util.m.a;
                this.b = new ArrayDeque(20);
                break;
            case 5:
                this.b = new androidx.appcompat.app.J(this, 24);
                break;
            case 6:
            case 10:
            case 12:
            default:
                this.b = C0776c.z(Boolean.FALSE);
                break;
            case 7:
                this.b = new HashMap();
                break;
            case 8:
                this.b = new com.quizlet.features.questiontypes.data.a(R.string.answer_label_fill_in_the_blank, null);
                break;
            case 9:
                break;
            case 11:
                this.b = com.quizlet.ui.resources.icons.c.c;
                break;
            case 13:
                this.b = new io.ktor.util.c();
                break;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public J0(Function1 mapper) {
        this.a = 1;
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        this.b = (kotlin.jvm.internal.r) mapper;
    }

    public J0(app.cash.sqldelight.driver.android.i driver) {
        this.a = 2;
        Intrinsics.checkNotNullParameter(driver, "driver");
        Intrinsics.checkNotNullParameter(driver, "driver");
        this.b = driver;
    }
}
