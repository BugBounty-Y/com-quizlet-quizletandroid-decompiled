package com.quizlet.data.repository.set;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.util.Rational;
import android.util.Size;
import android.view.View;
import android.webkit.MimeTypeMap;
import androidx.camera.core.impl.InterfaceC0183w;
import androidx.work.I;
import com.google.android.datatransport.cct.internal.s;
import com.google.android.datatransport.runtime.i;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.Q;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.google.android.gms.internal.play_billing.C3803i;
import com.google.common.base.h;
import com.google.firebase.messaging.p;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.OTCallback;
import com.onetrust.otpublishers.headless.Public.Response.OTResponse;
import com.onetrust.otpublishers.headless.Public.Response.OTResponseType;
import com.quizlet.data.model.C4180x1;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.joincontenttofolder.j;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import io.reactivex.rxjava3.internal.operators.single.g;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.m;
import kotlin.text.x;
import kotlinx.coroutines.AbstractC5040y;
import okhttp3.H;
import okhttp3.r;
import retrofit2.InterfaceC5179d;
import retrofit2.InterfaceC5182g;
import retrofit2.K;

/* loaded from: classes2.dex */
public final class f implements InterfaceC5182g {
    public final /* synthetic */ int a;
    public Object b;
    public Object c;
    public Object d;

    public /* synthetic */ f(int i) {
        this.a = i;
    }

    public static final C4180x1 a(f fVar, K k) {
        List listB;
        ApiThreeWrapper apiThreeWrapper = (ApiThreeWrapper) k.b;
        if (apiThreeWrapper == null || (listB = ((com.quizlet.remote.model.school.a) fVar.c).b(apiThreeWrapper)) == null) {
            listB = kotlin.collections.K.a;
        }
        r rVar = k.a.f;
        Intrinsics.checkNotNullExpressionValue(rVar, "headers(...)");
        return new C4180x1(Q.a(rVar), listB);
    }

    public static ArrayList j(ArrayList arrayList) {
        ArrayList arrayList2 = new ArrayList();
        arrayList2.add(androidx.camera.core.impl.utils.b.a);
        arrayList2.add(androidx.camera.core.impl.utils.b.c);
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Size size = (Size) it2.next();
            Rational rational = new Rational(size.getWidth(), size.getHeight());
            if (!arrayList2.contains(rational)) {
                Iterator it3 = arrayList2.iterator();
                while (true) {
                    if (!it3.hasNext()) {
                        arrayList2.add(rational);
                        break;
                    }
                    if (androidx.camera.core.impl.utils.b.a((Rational) it3.next(), size)) {
                        break;
                    }
                }
            }
        }
        return arrayList2;
    }

    public static Rational m(int i, boolean z) {
        if (i == -1) {
            return null;
        }
        if (i == 0) {
            return z ? androidx.camera.core.impl.utils.b.a : androidx.camera.core.impl.utils.b.b;
        }
        if (i == 1) {
            return z ? androidx.camera.core.impl.utils.b.c : androidx.camera.core.impl.utils.b.d;
        }
        AbstractC3053s1.c("SupportedOutputSizesCollector", "Undefined target aspect ratio: " + i);
        return null;
    }

    public static HashMap p(ArrayList arrayList) {
        HashMap map = new HashMap();
        Iterator it2 = j(arrayList).iterator();
        while (it2.hasNext()) {
            map.put((Rational) it2.next(), new ArrayList());
        }
        Iterator it3 = arrayList.iterator();
        while (it3.hasNext()) {
            Size size = (Size) it3.next();
            for (Rational rational : map.keySet()) {
                if (androidx.camera.core.impl.utils.b.a(rational, size)) {
                    ((List) map.get(rational)).add(size);
                }
            }
        }
        return map;
    }

    public static void t(List list, Size size, boolean z) {
        ArrayList arrayList = new ArrayList();
        for (int size2 = list.size() - 1; size2 >= 0; size2--) {
            Size size3 = (Size) list.get(size2);
            if (size3.getWidth() >= size.getWidth() && size3.getHeight() >= size.getHeight()) {
                break;
            }
            arrayList.add(0, size3);
        }
        list.removeAll(arrayList);
        Collections.reverse(list);
        if (z) {
            list.addAll(arrayList);
        }
    }

    public static void u(List list, Size size, boolean z) {
        ArrayList arrayList = new ArrayList();
        for (int i = 0; i < list.size(); i++) {
            Size size2 = (Size) list.get(i);
            if (size2.getWidth() <= size.getWidth() && size2.getHeight() <= size.getHeight()) {
                break;
            }
            arrayList.add(0, size2);
        }
        list.removeAll(arrayList);
        if (z) {
            list.addAll(arrayList);
        }
    }

    public i b() {
        String strConcat = ((String) this.b) == null ? " backendName" : "";
        if (((com.google.android.datatransport.d) this.d) == null) {
            strConcat = strConcat.concat(" priority");
        }
        if (strConcat.isEmpty()) {
            return new i((String) this.b, (byte[]) this.c, (com.google.android.datatransport.d) this.d);
        }
        throw new IllegalStateException("Missing required properties:".concat(strConcat));
    }

    /* JADX WARN: Code restructure failed: missing block: B:26:0x0065, code lost:
    
        if (r7 == r1) goto L27;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object c(kotlin.coroutines.jvm.internal.c r7) {
        /*
            r6 = this;
            boolean r0 = r7 instanceof com.quizlet.featuregate.features.studymodes.a
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.featuregate.features.studymodes.a r0 = (com.quizlet.featuregate.features.studymodes.a) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.featuregate.features.studymodes.a r0 = new com.quizlet.featuregate.features.studymodes.a
            r0.<init>(r6, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L36
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L68
        L2a:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L32:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            return r7
        L36:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Object r7 = r6.b
            androidx.work.impl.model.c r7 = (androidx.work.impl.model.c) r7
            com.quizlet.generated.enums.J r2 = r7.k()
            com.quizlet.generated.enums.H r7 = r7.g()
            com.quizlet.generated.enums.J r5 = com.quizlet.generated.enums.J.PORTUGUESE
            if (r2 != r5) goto L5f
            com.quizlet.generated.enums.H r2 = com.quizlet.generated.enums.H.BRAZIL
            if (r7 != r2) goto L5f
            r0.l = r4
            java.lang.Object r7 = r6.d
            com.quizlet.remote.model.notes.e r7 = (com.quizlet.remote.model.notes.e) r7
            java.lang.Object r0 = r7.e
            java.lang.Enum r0 = (java.lang.Enum) r0
            java.lang.Enum r7 = r7.k(r0)
            if (r7 != r1) goto L5e
            goto L67
        L5e:
            return r7
        L5f:
            r0.l = r3
            java.lang.Object r7 = r6.r(r0)
            if (r7 != r1) goto L68
        L67:
            return r1
        L68:
            java.lang.Boolean r7 = (java.lang.Boolean) r7
            boolean r7 = r7.booleanValue()
            if (r7 == 0) goto L73
            com.quizlet.featuregate.contracts.enums.a r7 = com.quizlet.featuregate.contracts.enums.a.b
            return r7
        L73:
            com.quizlet.featuregate.contracts.enums.a r7 = com.quizlet.featuregate.contracts.enums.a.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.set.f.c(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object d(java.lang.String r5, kotlin.coroutines.jvm.internal.c r6) throws java.lang.Throwable {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.quizletandroid.util.file.a
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.quizletandroid.util.file.a r0 = (com.quizlet.quizletandroid.util.file.a) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.util.file.a r0 = new com.quizlet.quizletandroid.util.file.a
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L45
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            com.quizlet.quizletandroid.util.file.b r6 = new com.quizlet.quizletandroid.util.file.b
            r2 = 0
            r6.<init>(r4, r5, r2)
            r0.l = r3
            java.lang.Object r5 = r4.d
            kotlinx.coroutines.y r5 = (kotlinx.coroutines.AbstractC5040y) r5
            java.lang.Object r6 = kotlinx.coroutines.E.J(r5, r6, r0)
            if (r6 != r1) goto L45
            return r1
        L45:
            java.lang.String r5 = "withContext(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r6, r5)
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.set.f.d(java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x0057  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object e(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof com.quizlet.data.repository.set.e
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.data.repository.set.e r0 = (com.quizlet.data.repository.set.e) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.data.repository.set.e r0 = new com.quizlet.data.repository.set.e
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            com.quizlet.data.repository.set.f r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r5)     // Catch: java.lang.Exception -> L29
            goto L4a
        L29:
            r5 = move-exception
            goto L51
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            java.lang.Object r5 = r4.b     // Catch: java.lang.Exception -> L4f
            com.google.firebase.messaging.p r5 = (com.google.firebase.messaging.p) r5     // Catch: java.lang.Exception -> L4f
            java.lang.Object r5 = r5.b     // Catch: java.lang.Exception -> L4f
            com.quizlet.remote.model.set.d r5 = (com.quizlet.remote.model.set.d) r5     // Catch: java.lang.Exception -> L4f
            r0.j = r4     // Catch: java.lang.Exception -> L4f
            r0.m = r3     // Catch: java.lang.Exception -> L4f
            java.lang.Object r5 = r5.d(r0)     // Catch: java.lang.Exception -> L4f
            if (r5 != r1) goto L49
            return r1
        L49:
            r0 = r4
        L4a:
            com.quizlet.data.model.s1 r5 = (com.quizlet.data.model.AbstractC4165s1) r5     // Catch: java.lang.Exception -> L29
            return r5
        L4d:
            r0 = r4
            goto L51
        L4f:
            r5 = move-exception
            goto L4d
        L51:
            boolean r1 = com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3746v6.b(r5)
            if (r1 != 0) goto L60
            java.lang.Object r0 = r0.d
            org.slf4j.b r0 = (org.slf4j.b) r0
            java.lang.String r1 = "Error from remote"
            r0.j(r1, r5)
        L60:
            com.quizlet.data.model.p1 r5 = new com.quizlet.data.model.p1
            kotlin.collections.K r0 = kotlin.collections.K.a
            r5.<init>(r0)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.set.f.e(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // retrofit2.InterfaceC5182g
    public void f(InterfaceC5179d interfaceC5179d, Throwable th) {
        OTLogger.c("NetworkRequestHandler", 6, " IAB Vendorlist Api Failed  :  " + th.getMessage());
        OTCallback oTCallback = (OTCallback) this.b;
        if (oTCallback != null) {
            new com.onetrust.otpublishers.headless.Internal.profile.c(((com.onetrust.otpublishers.headless.Internal.Network.d) this.d).a).b();
            oTCallback.onFailure(new OTResponse(OTResponseType.OT_ERROR, 102, " IAB Vendorlist Api Failed ", ""));
        }
    }

    public int g(int i) {
        int i2;
        int iOrdinal = n().ordinal();
        if (iOrdinal == 0) {
            i2 = R.style.AssemblyTheme;
        } else if (iOrdinal == 1) {
            i2 = R.style.AssemblyDayTheme;
        } else {
            if (iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
            i2 = R.style.AssemblyNightTheme;
        }
        return com.quizlet.themes.extensions.a.a(new androidx.appcompat.view.d((Context) this.b, i2), i);
    }

    public String h(String uriString) {
        Intrinsics.checkNotNullParameter(uriString, "uriString");
        Uri uri = (Uri) ((com.quizlet.quizletandroid.ui.common.images.capture.a) this.c).h(uriString);
        String type = ((Context) this.b).getContentResolver().getType(uri);
        if (type != null) {
            return type;
        }
        String fileExtensionFromUrl = MimeTypeMap.getFileExtensionFromUrl(uri.toString());
        MimeTypeMap singleton = MimeTypeMap.getSingleton();
        Intrinsics.d(fileExtensionFromUrl);
        String lowerCase = fileExtensionFromUrl.toLowerCase(Locale.ROOT);
        Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
        return singleton.getMimeTypeFromExtension(lowerCase);
    }

    public Object i(long j, kotlin.coroutines.jvm.internal.i iVar) {
        g gVarG = com.quizlet.local.ormlite.util.b.b(((p) this.d).i(), x.c("\n                SELECT * FROM term\n                WHERE setId = " + j + "\n                AND isDeleted = 0\n                ORDER by orderId ASC\n        ")).g(new com.quizlet.local.ormlite.models.term.b((com.quizlet.local.ormlite.models.term.a) this.c, 0));
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        return I1.b(gVarG, iVar);
    }

    @Override // retrofit2.InterfaceC5182g
    public void k(InterfaceC5179d interfaceC5179d, K k) {
        OTLogger.c("NetworkRequestHandler", 4, " IAB Vendorlist Api Success : " + ((String) k.b));
        H h = k.a;
        long j = h.l - h.k;
        OTLogger.c("OneTrust", 3, String.format("%s %d.%d s", "Time taken for IAB Vendor data fetch: ", Long.valueOf(TimeUnit.MILLISECONDS.toSeconds(j)), Long.valueOf(j % 1000)));
        new Thread(new I(this, k, (OTCallback) this.b, new Handler(Looper.getMainLooper()), (OTResponse) this.c, 3)).start();
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x00d0  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.util.ArrayList l(androidx.camera.core.impl.A0 r14) {
        /*
            Method dump skipped, instructions count: 895
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.set.f.l(androidx.camera.core.impl.A0):java.util.ArrayList");
    }

    public com.quizlet.themes.nighttheme.a n() {
        com.quizlet.themes.nighttheme.a aVar;
        com.quizlet.quizletandroid.ui.setcreation.adapters.a aVar2 = com.quizlet.themes.nighttheme.a.b;
        com.quizlet.quizletandroid.ui.setcreation.adapters.a aVar3 = com.quizlet.themes.nighttheme.a.b;
        int i = ((SharedPreferences) this.c).getInt("CUR_THEME", -1);
        aVar2.getClass();
        com.quizlet.themes.nighttheme.a[] aVarArrValues = com.quizlet.themes.nighttheme.a.values();
        int length = aVarArrValues.length;
        int i2 = 0;
        while (true) {
            if (i2 >= length) {
                aVar = null;
                break;
            }
            aVar = aVarArrValues[i2];
            if (aVar.a == i) {
                break;
            }
            i2++;
        }
        if (aVar != null) {
            return aVar;
        }
        throw new RuntimeException(android.support.v4.media.session.a.f(i, "Could not find theme corresponding to given id: "));
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object o(com.quizlet.studiablemodels.grading.d r10, com.quizlet.studiablemodels.grading.TrueFalseResponse r11, boolean r12, kotlin.coroutines.jvm.internal.c r13) {
        /*
            Method dump skipped, instructions count: 213
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.set.f.o(com.quizlet.studiablemodels.grading.d, com.quizlet.studiablemodels.grading.TrueFalseResponse, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public boolean q() {
        int iOrdinal = n().ordinal();
        if (iOrdinal != 0) {
            if (iOrdinal == 1) {
                return false;
            }
            if (iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
        } else if ((((Context) this.b).getResources().getConfiguration().uiMode & 48) != 32) {
            return false;
        }
        return true;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object r(kotlin.coroutines.jvm.internal.c r8) {
        /*
            r7 = this;
            boolean r0 = r8 instanceof com.quizlet.featuregate.features.studymodes.b
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.featuregate.features.studymodes.b r0 = (com.quizlet.featuregate.features.studymodes.b) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            com.quizlet.featuregate.features.studymodes.b r0 = new com.quizlet.featuregate.features.studymodes.b
            r0.<init>(r7, r8)
        L18:
            java.lang.Object r8 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3c
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r8)
            return r8
        L2a:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L32:
            com.quizlet.generated.enums.H r2 = r0.l
            com.quizlet.generated.enums.J r4 = r0.k
            com.quizlet.data.repository.set.f r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L5d
        L3c:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            java.lang.Object r8 = r7.b
            androidx.work.impl.model.c r8 = (androidx.work.impl.model.c) r8
            com.quizlet.generated.enums.J r2 = r8.k()
            com.quizlet.generated.enums.H r5 = r8.g()
            r0.j = r7
            r0.k = r2
            r0.l = r5
            r0.o = r4
            java.lang.Enum r8 = r8.d(r0)
            if (r8 != r1) goto L5a
            goto L7c
        L5a:
            r4 = r2
            r2 = r5
            r5 = r7
        L5d:
            com.quizlet.generated.enums.H r8 = (com.quizlet.generated.enums.H) r8
            com.quizlet.generated.enums.J r6 = com.quizlet.generated.enums.J.SPANISH
            if (r4 != r6) goto L7e
            com.quizlet.generated.enums.H r4 = com.quizlet.generated.enums.H.MEXICO
            if (r2 == r4) goto L69
            if (r8 != r4) goto L7e
        L69:
            java.lang.Object r8 = r5.c
            com.quizlet.data.repository.user.a r8 = (com.quizlet.data.repository.user.a) r8
            r2 = 0
            r0.j = r2
            r0.k = r2
            r0.l = r2
            r0.o = r3
            java.lang.Object r8 = r8.j(r0)
            if (r8 != r1) goto L7d
        L7c:
            return r1
        L7d:
            return r8
        L7e:
            java.lang.Boolean r8 = java.lang.Boolean.FALSE
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.set.f.r(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public void s(String str) {
        if (str == null) {
            throw new NullPointerException("Null backendName");
        }
        this.b = str;
    }

    public String toString() {
        switch (this.a) {
            case 3:
                StringBuilder sb = new StringBuilder("NavDeepLinkRequest{");
                Uri uri = (Uri) this.b;
                if (uri != null) {
                    sb.append(" uri=");
                    sb.append(String.valueOf(uri));
                }
                String str = (String) this.c;
                if (str != null) {
                    sb.append(" action=");
                    sb.append(str);
                }
                String str2 = (String) this.d;
                if (str2 != null) {
                    sb.append(" mimetype=");
                    sb.append(str2);
                }
                sb.append(" }");
                String string = sb.toString();
                Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                return string;
            case 4:
            case 5:
            default:
                return super.toString();
            case 6:
                StringBuilder sb2 = new StringBuilder(32);
                sb2.append((String) this.b);
                sb2.append('{');
                com.quizlet.data.repository.login.a aVar = (com.quizlet.data.repository.login.a) ((com.quizlet.data.repository.login.a) this.c).c;
                String str3 = "";
                while (aVar != null) {
                    Object obj = aVar.b;
                    sb2.append(str3);
                    String str4 = (String) aVar.a;
                    if (str4 != null) {
                        sb2.append(str4);
                        sb2.append('=');
                    }
                    if (obj == null || !obj.getClass().isArray()) {
                        sb2.append(obj);
                    } else {
                        sb2.append((CharSequence) Arrays.deepToString(new Object[]{obj}), 1, r2.length() - 1);
                    }
                    aVar = (com.quizlet.data.repository.login.a) aVar.c;
                    str3 = ", ";
                }
                sb2.append('}');
                return sb2.toString();
            case 7:
                StringBuilder sb3 = new StringBuilder(32);
                sb3.append((String) this.b);
                sb3.append('{');
                C3803i c3803i = ((C3803i) this.c).b;
                String str5 = "";
                while (c3803i != null) {
                    Object obj2 = c3803i.a;
                    sb3.append(str5);
                    if (obj2 == null || !obj2.getClass().isArray()) {
                        sb3.append(obj2);
                    } else {
                        sb3.append((CharSequence) Arrays.deepToString(new Object[]{obj2}), 1, r2.length() - 1);
                    }
                    c3803i = c3803i.b;
                    str5 = ", ";
                }
                sb3.append('}');
                return sb3.toString();
            case 8:
                StringBuilder sb4 = new StringBuilder(32);
                sb4.append((String) this.b);
                sb4.append('{');
                com.quizlet.data.repository.login.a aVar2 = (com.quizlet.data.repository.login.a) ((com.quizlet.data.repository.login.a) this.c).c;
                String str6 = "";
                while (aVar2 != null) {
                    Object obj3 = aVar2.b;
                    boolean z = aVar2 instanceof h;
                    sb4.append(str6);
                    String str7 = (String) aVar2.a;
                    if (str7 != null) {
                        sb4.append(str7);
                        sb4.append('=');
                    }
                    if (obj3 == null || !obj3.getClass().isArray()) {
                        sb4.append(obj3);
                    } else {
                        String strDeepToString = Arrays.deepToString(new Object[]{obj3});
                        sb4.append((CharSequence) strDeepToString, 1, strDeepToString.length() - 1);
                    }
                    aVar2 = (com.quizlet.data.repository.login.a) aVar2.c;
                    str6 = ", ";
                }
                sb4.append('}');
                return sb4.toString();
        }
    }

    public void v(String str, Object obj) {
        com.quizlet.data.repository.login.a aVar = new com.quizlet.data.repository.login.a();
        ((com.quizlet.data.repository.login.a) this.d).c = aVar;
        this.d = aVar;
        aVar.b = obj;
        aVar.a = str;
    }

    public f(com.onetrust.otpublishers.headless.Internal.Network.d dVar, OTCallback oTCallback, OTResponse oTResponse) {
        this.a = 9;
        this.d = dVar;
        this.b = oTCallback;
        this.c = oTResponse;
    }

    public f(String str, int i) {
        this.a = i;
        switch (i) {
            case 7:
                C3803i c3803i = new C3803i();
                this.c = c3803i;
                this.d = c3803i;
                this.b = str;
                break;
            case 8:
                com.quizlet.data.repository.login.a aVar = new com.quizlet.data.repository.login.a();
                this.c = aVar;
                this.d = aVar;
                this.b = str;
                break;
            default:
                com.quizlet.data.repository.login.a aVar2 = new com.quizlet.data.repository.login.a();
                this.c = aVar2;
                this.d = aVar2;
                this.b = str;
                break;
        }
    }

    public f(com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager, com.quizlet.braze.e brazeUserManager, com.quizlet.infra.legacysyncengine.net.f syncDispatcher) {
        this.a = 14;
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(brazeUserManager, "brazeUserManager");
        Intrinsics.checkNotNullParameter(syncDispatcher, "syncDispatcher");
        this.b = loggedInUserManager;
        this.c = brazeUserManager;
        this.d = syncDispatcher;
    }

    public f(androidx.work.impl.model.c userProps, com.quizlet.data.repository.user.a mexicanSpanishFeature, com.quizlet.remote.model.notes.e brazilianLearnCopyUpdate) {
        this.a = 11;
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        Intrinsics.checkNotNullParameter(mexicanSpanishFeature, "mexicanSpanishFeature");
        Intrinsics.checkNotNullParameter(brazilianLearnCopyUpdate, "brazilianLearnCopyUpdate");
        this.b = userProps;
        this.c = mexicanSpanishFeature;
        this.d = brazilianLearnCopyUpdate;
    }

    public f(s database, ModelIdentityProvider modelIdentityProvider, com.quizlet.local.ormlite.models.term.a mapper) {
        this.a = 13;
        Intrinsics.checkNotNullParameter(database, "database");
        Intrinsics.checkNotNullParameter(modelIdentityProvider, "modelIdentityProvider");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        this.b = modelIdentityProvider;
        this.c = mapper;
        this.d = (p) database.h;
    }

    public f(com.quizlet.data.repository.progress.b defaultRepository, androidx.work.impl.model.c dispatcher, com.google.mlkit.vision.documentscanner.internal.c syncUtil) {
        this.a = 10;
        Intrinsics.checkNotNullParameter(defaultRepository, "defaultRepository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        Intrinsics.checkNotNullParameter(syncUtil, "syncUtil");
        this.b = defaultRepository;
        this.c = dispatcher;
        this.d = syncUtil;
    }

    public f(Context context, SharedPreferences sharedPreferences, EventLogger eventLogger) {
        this.a = 18;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.b = context;
        this.c = sharedPreferences;
        this.d = eventLogger;
    }

    public f(p factory, com.quizlet.data.connectivity.a networkStatus, org.slf4j.b logger) {
        this.a = 0;
        Intrinsics.checkNotNullParameter(factory, "factory");
        Intrinsics.checkNotNullParameter(networkStatus, "networkStatus");
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.b = factory;
        this.c = networkStatus;
        this.d = logger;
    }

    public f(com.quizlet.features.questiontypes.basequestion.c answerLabelUseCase) {
        this.a = 12;
        Intrinsics.checkNotNullParameter(answerLabelUseCase, "answerLabelUseCase");
    }

    public f(com.quizlet.remote.service.x service, com.quizlet.remote.model.school.a schoolMapper, AbstractC5040y ioDispatcher) {
        this.a = 17;
        Intrinsics.checkNotNullParameter(service, "service");
        Intrinsics.checkNotNullParameter(schoolMapper, "schoolMapper");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.b = service;
        this.c = schoolMapper;
        this.d = ioDispatcher;
    }

    public f(long j, com.quizlet.infra.legacysyncengine.net.c cVar) {
        this.a = 15;
        com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.STUDY_SET);
        Relationship<DBStudySet, DBUser> relationship = DBStudySetFields.CREATOR;
        bVar.b(Long.valueOf(j), relationship);
        bVar.e(relationship);
        bVar.a();
        this.b = new com.quizlet.infra.legacysyncengine.datasources.h(cVar, Long.valueOf(j));
        this.c = new com.quizlet.infra.legacysyncengine.datasources.p(cVar, Long.valueOf(j), 3);
        this.d = new com.quizlet.infra.legacysyncengine.datasources.p(cVar, Long.valueOf(j), 0);
    }

    public f(Context context, com.quizlet.quizletandroid.ui.common.images.capture.a uriCreator, AbstractC5040y dispatcher) {
        this.a = 16;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(uriCreator, "uriCreator");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = context;
        this.c = uriCreator;
        this.d = dispatcher;
    }

    public f(j logger, org.koin.core.scope.a scope, org.koin.core.parameter.a aVar) {
        this.a = 19;
        Intrinsics.checkNotNullParameter(logger, "logger");
        Intrinsics.checkNotNullParameter(scope, "scope");
        this.b = logger;
        this.c = scope;
        this.d = aVar;
    }

    public f(Uri uri, String str, String str2) {
        this.a = 3;
        this.b = uri;
        this.c = str;
        this.d = str2;
    }

    public f(View view) {
        this.a = 2;
        this.b = view;
        this.c = l.a(m.c, new androidx.compose.ui.input.nestedscroll.b(this, 11));
        this.d = new com.quizlet.data.repository.school.membership.a(view);
    }

    public f(InterfaceC0183w interfaceC0183w, Size size) {
        Rational rational;
        this.a = 1;
        this.b = interfaceC0183w;
        interfaceC0183w.a();
        interfaceC0183w.e();
        if (size != null) {
            rational = new Rational(size.getWidth(), size.getHeight());
        } else {
            List listI = interfaceC0183w.i(256);
            if (listI.isEmpty()) {
                rational = null;
            } else {
                Size size2 = (Size) Collections.max(listI, new androidx.camera.core.impl.utils.c(false));
                rational = new Rational(size2.getWidth(), size2.getHeight());
            }
        }
        this.c = rational;
        this.d = new androidx.camera.core.internal.j(interfaceC0183w, rational);
    }
}
