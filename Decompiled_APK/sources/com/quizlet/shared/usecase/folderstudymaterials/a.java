package com.quizlet.shared.usecase.folderstudymaterials;

import android.content.Context;
import android.graphics.Bitmap;
import android.webkit.WebSettings;
import android.webkit.WebView;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.datastore.core.CorruptionException;
import androidx.datastore.core.InterfaceC1070b;
import com.amazon.device.ads.AdRegistration;
import com.bumptech.glide.load.resource.bitmap.n;
import com.google.android.gms.internal.measurement.C3021l3;
import com.google.android.gms.internal.measurement.H2;
import com.google.android.gms.internal.measurement.O2;
import com.google.android.gms.internal.measurement.Q2;
import com.google.android.gms.internal.measurement.Z2;
import com.google.android.gms.internal.measurement.e4;
import com.google.android.gms.internal.mlkit_common.u;
import com.google.android.gms.internal.mlkit_vision_barcode.A4;
import com.google.android.gms.internal.mlkit_vision_barcode.B4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3771z;
import com.google.android.gms.measurement.internal.AbstractC3893t;
import com.google.android.gms.measurement.internal.Z;
import com.google.android.gms.measurement.internal.r;
import com.quizlet.data.model.E;
import com.quizlet.db.data.models.persisted.DBGroupMembership;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.generated.enums.C4523u;
import com.quizlet.generated.enums.EnumC4526v;
import io.reactivex.rxjava3.core.p;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public final class a implements e, InterfaceC1070b, n, com.bumptech.glide.util.pool.c, com.google.android.gms.dynamite.a, r, com.google.firebase.crashlytics.internal.metadata.d, com.google.gson.internal.n, com.google.zxing.b, androidx.lifecycle.viewmodel.b, com.quizlet.local.ormlite.util.c {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    public static androidx.compose.material3.windowsizeclass.b m(long j) {
        Set set = androidx.compose.material3.windowsizeclass.c.b;
        Set set2 = androidx.compose.material3.windowsizeclass.a.b;
        float fB = androidx.compose.ui.unit.g.b(j);
        int i = 0;
        float f = 0;
        if (Float.compare(fB, f) < 0) {
            throw new IllegalArgumentException("Width must not be negative");
        }
        if (set.isEmpty()) {
            throw new IllegalArgumentException("Must support at least one size class");
        }
        List list = androidx.compose.material3.windowsizeclass.c.c;
        int size = list.size();
        int i2 = 0;
        int i3 = 0;
        while (true) {
            if (i2 >= size) {
                break;
            }
            int i4 = ((androidx.compose.material3.windowsizeclass.c) list.get(i2)).a;
            if (set.contains(new androidx.compose.material3.windowsizeclass.c(i4))) {
                if (Float.compare(fB, B4.a(i4)) >= 0) {
                    i3 = i4;
                    break;
                }
                i3 = i4;
            }
            i2++;
        }
        Set set3 = androidx.compose.material3.windowsizeclass.a.b;
        float fA = androidx.compose.ui.unit.g.a(j);
        if (Float.compare(fA, f) < 0) {
            throw new IllegalArgumentException("Width must not be negative");
        }
        if (set2.isEmpty()) {
            throw new IllegalArgumentException("Must support at least one size class");
        }
        List list2 = androidx.compose.material3.windowsizeclass.a.c;
        int size2 = list2.size();
        int i5 = 2;
        while (true) {
            if (i >= size2) {
                break;
            }
            int i6 = ((androidx.compose.material3.windowsizeclass.a) list2.get(i)).a;
            if (set2.contains(new androidx.compose.material3.windowsizeclass.a(i6))) {
                if (Float.compare(fA, A4.a(i6)) >= 0) {
                    i5 = i6;
                    break;
                }
                i5 = i6;
            }
            i++;
        }
        return new androidx.compose.material3.windowsizeclass.b(i3, i5);
    }

    public static void n(com.amazon.aps.ads.util.adview.e webView) {
        Intrinsics.checkNotNullParameter(webView, "webView");
        WebSettings settings = webView.getSettings();
        if (settings == null) {
            return;
        }
        int i = com.amazon.aps.ads.a.a;
        WebView.setWebContentsDebuggingEnabled(AdRegistration.isTestMode());
        settings.setJavaScriptEnabled(true);
        settings.setAllowContentAccess(true);
        settings.setDomStorageEnabled(true);
        settings.setAppCacheEnabled(true);
        settings.setAllowFileAccess(false);
        settings.setLoadsImagesAutomatically(true);
        settings.setMediaPlaybackRequiresUserGesture(false);
        settings.setBlockNetworkImage(false);
    }

    public static boolean p(List listOfTerms, boolean z) {
        Intrinsics.checkNotNullParameter(listOfTerms, "listOfTerms");
        Iterator it2 = CollectionsKt.J(listOfTerms).iterator();
        int i = 0;
        while (true) {
            boolean z2 = true;
            if (!it2.hasNext()) {
                break;
            }
            DBTerm dBTerm = (DBTerm) it2.next();
            String word = dBTerm.getWord();
            boolean z3 = word == null || StringsKt.O(word);
            String definition = dBTerm.getDefinition();
            if ((definition == null || StringsKt.O(definition)) && !dBTerm.hasDefinitionImage()) {
                z2 = false;
            }
            if (!z3 && z2) {
                i++;
            }
        }
        return !z && i >= 6;
    }

    @Override // com.google.gson.internal.n
    public Object E() {
        return new ArrayList();
    }

    @Override // com.google.firebase.crashlytics.internal.metadata.d
    public void a() {
    }

    @Override // androidx.datastore.core.InterfaceC1070b
    public Object b(CorruptionException corruptionException) throws CorruptionException {
        throw corruptionException;
    }

    @Override // com.bumptech.glide.load.resource.bitmap.n
    public void c(Bitmap bitmap, com.bumptech.glide.load.engine.bitmap_recycle.a aVar) {
    }

    @Override // com.google.android.gms.dynamite.a
    public int d(Context context, String str, boolean z) {
        return com.google.android.gms.dynamite.c.d(context, str, z);
    }

    @Override // com.google.android.gms.dynamite.a
    public int e(Context context, String str) {
        return com.google.android.gms.dynamite.c.a(context, str);
    }

    @Override // com.google.firebase.crashlytics.internal.metadata.d
    public String f() {
        return null;
    }

    @Override // com.quizlet.local.ormlite.util.c
    public ArrayList g(List list) {
        return AbstractC3771z.c(this, list);
    }

    @Override // com.quizlet.local.ormlite.util.c
    public Object h(Object obj) {
        DBGroupMembership local = (DBGroupMembership) obj;
        Intrinsics.checkNotNullParameter(local, "local");
        long userId = local.getUserId();
        long classId = local.getClassId();
        int lastVisited = local.getLastVisited();
        C4523u c4523u = EnumC4526v.Companion;
        int level = local.getLevel();
        c4523u.getClass();
        EnumC4526v[] enumC4526vArrValues = EnumC4526v.values();
        int length = enumC4526vArrValues.length;
        int i = 0;
        while (i < length) {
            int i2 = level;
            EnumC4526v enumC4526v = enumC4526vArrValues[i];
            if (enumC4526v.a() == i2) {
                return new E(userId, classId, lastVisited, enumC4526v, local.getReceiveEmail(), local.getTimestamp(), (int) local.getLastModified());
            }
            i++;
            level = i2;
        }
        throw new NoSuchElementException("Array contains no element matching the predicate.");
    }

    @Override // com.bumptech.glide.load.resource.bitmap.n
    public void i() {
    }

    @Override // com.google.firebase.crashlytics.internal.metadata.d
    public void j(long j, String str) {
    }

    @Override // com.bumptech.glide.util.pool.c
    public void k(Object obj) {
        ((List) obj).clear();
    }

    @Override // com.google.zxing.b
    public com.google.zxing.common.b l(String str, int i, int i2, int i3, EnumMap enumMap) {
        com.google.zxing.b bVar;
        switch (AbstractC0147y.k(i)) {
            case 0:
                bVar = new b(20);
                break;
            case 1:
                bVar = new com.google.zxing.oned.b();
                break;
            case 2:
                bVar = new com.google.zxing.oned.g(2);
                break;
            case 3:
                bVar = new com.google.zxing.oned.g(3);
                break;
            case 4:
                bVar = new com.google.zxing.oned.g(1);
                break;
            case 5:
                bVar = new c(20);
                break;
            case 6:
                bVar = new com.google.zxing.oned.f(1);
                break;
            case 7:
                bVar = new com.google.zxing.oned.f(0);
                break;
            case 8:
                bVar = new com.google.zxing.oned.g(0);
                break;
            case 9:
            case 12:
            case 13:
            default:
                throw new IllegalArgumentException("No encoder available for format ".concat(Z.t(i)));
            case 10:
                bVar = new assistantMode.utils.studiableMetadata.b(21);
                break;
            case 11:
                bVar = new u(21);
                break;
            case 14:
                bVar = new com.airbnb.lottie.network.c(29);
                break;
            case 15:
                bVar = new com.google.zxing.oned.f(2);
                break;
        }
        return bVar.l(str, i, i2, i3, enumMap);
    }

    public p o(androidx.work.impl.model.c userProps) {
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        return com.google.android.gms.dynamite.d.e(userProps.u());
    }

    @Override // com.google.android.gms.measurement.internal.r
    public Object zza() {
        switch (this.a) {
            case 10:
                List list = AbstractC3893t.a;
                Boolean bool = (Boolean) e4.a.b();
                bool.getClass();
                return bool;
            case 11:
                List list2 = AbstractC3893t.a;
                Boolean bool2 = (Boolean) H2.a.b();
                bool2.getClass();
                return bool2;
            case 12:
                Boolean bool3 = (Boolean) C3021l3.a.b();
                bool3.getClass();
                return bool3;
            case 13:
                List list3 = AbstractC3893t.a;
                O2.b.get();
                Long l = (Long) Q2.b.b();
                l.getClass();
                return l;
            case 14:
                List list4 = AbstractC3893t.a;
                O2.b.get();
                Long l2 = (Long) Q2.e0.b();
                l2.getClass();
                return l2;
            case 15:
                List list5 = AbstractC3893t.a;
                O2.b.get();
                Long l3 = (Long) Q2.E.b();
                l3.getClass();
                return l3;
            case 16:
                List list6 = AbstractC3893t.a;
                Boolean bool4 = (Boolean) Z2.b.b();
                bool4.getClass();
                return bool4;
            default:
                List list7 = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.U.b()).longValue());
        }
    }
}
