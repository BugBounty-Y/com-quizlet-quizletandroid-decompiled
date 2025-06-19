package com.quizlet.features.notes.detail.navigation;

import android.app.Activity;
import android.content.Context;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.navigation.E;
import androidx.navigation.H;
import androidx.navigation.W;
import androidx.navigation.compose.C1278k;
import androidx.navigation.compose.C1280m;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_common.u;
import com.google.android.gms.internal.mlkit_vision_barcode.N5;
import com.google.android.gms.internal.mlkit_vision_camera.O1;
import com.google.android.gms.internal.mlkit_vision_camera.Q1;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.assembly.compose.buttons.C4087l;
import com.quizlet.data.model.m2;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import com.quizlet.features.notes.upload.UploadNotesActivity;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.webpages.WebViewActivity;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class f {
    public static final /* synthetic */ int a = 0;
    public static final /* synthetic */ int b = 0;

    public static final void a(final String magicNotesUuid, final com.quizlet.features.notes.manager.a navigationManager, final boolean z, final AddMaterialFolderData addMaterialFolderData, H h, InterfaceC0806l interfaceC0806l, int i) {
        H hD;
        int i2;
        H h2;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(magicNotesUuid, "magicNotesUuid");
        Intrinsics.checkNotNullParameter(navigationManager, "navigationManager");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1492864599);
        int i3 = i | (c0814p2.f(magicNotesUuid) ? 4 : 2) | (c0814p2.f(navigationManager) ? 32 : 16) | (c0814p2.g(z) ? 256 : 128) | (c0814p2.h(addMaterialFolderData) ? 2048 : 1024) | 8192;
        if ((i3 & 9363) == 9362 && c0814p2.x()) {
            c0814p2.Q();
            h2 = h;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i & 1) == 0 || c0814p2.w()) {
                hD = O1.d(new W[0], c0814p2);
                i2 = i3 & (-57345);
            } else {
                c0814p2.Q();
                i2 = i3 & (-57345);
                hD = h;
            }
            c0814p2.q();
            final Context context = (Context) c0814p2.j(AndroidCompositionLocals_androidKt.b);
            c0814p2.X(1653566386);
            Object objI = c0814p2.I();
            V v = C0804k.a;
            if (objI == v) {
                objI = new C1278k(navigationManager, 13);
                c0814p2.i0(objI);
            }
            final Function2 function2 = (Function2) objI;
            Object objG = Z.g(1653571133, c0814p2, false);
            if (objG == v) {
                final int i4 = 0;
                objG = new Function0() { // from class: com.quizlet.features.notes.detail.navigation.a
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        com.quizlet.features.notes.manager.a aVar = navigationManager;
                        Context context2 = context;
                        switch (i4) {
                            case 0:
                                Intrinsics.e(context2, "null cannot be cast to non-null type android.app.Activity");
                                Activity context3 = (Activity) context2;
                                ((com.quizlet.quizletandroid.ui.navigationmanagers.e) aVar).getClass();
                                Intrinsics.checkNotNullParameter(context3, "context");
                                context3.finish();
                                break;
                            case 1:
                                com.quizlet.quizletandroid.ui.navigationmanagers.e eVar = (com.quizlet.quizletandroid.ui.navigationmanagers.e) aVar;
                                eVar.getClass();
                                int i5 = UploadNotesActivity.i;
                                eVar.b(u.i(eVar.a, m2.a, null, null, null, 28));
                                Intrinsics.e(context2, "null cannot be cast to non-null type android.app.Activity");
                                Activity context4 = (Activity) context2;
                                eVar.getClass();
                                Intrinsics.checkNotNullParameter(context4, "context");
                                context4.finish();
                                break;
                            case 2:
                                String url = context2.getString(R.string.magic_notes_detail_help_center_url);
                                Intrinsics.checkNotNullExpressionValue(url, "getString(...)");
                                String title = context2.getString(R.string.user_settings_help_center);
                                Intrinsics.checkNotNullExpressionValue(title, "getString(...)");
                                com.quizlet.quizletandroid.ui.navigationmanagers.e eVar2 = (com.quizlet.quizletandroid.ui.navigationmanagers.e) aVar;
                                eVar2.getClass();
                                Intrinsics.checkNotNullParameter(url, "url");
                                Intrinsics.checkNotNullParameter(title, "title");
                                String str = WebViewActivity.u;
                                eVar2.b(com.quizlet.features.setpage.utils.activities.a.a(eVar2.a, url, title));
                                break;
                            default:
                                String url2 = context2.getString(R.string.magic_notes_detail_terms_of_service_url);
                                Intrinsics.checkNotNullExpressionValue(url2, "getString(...)");
                                String title2 = context2.getString(R.string.user_settings_terms_of_service);
                                Intrinsics.checkNotNullExpressionValue(title2, "getString(...)");
                                com.quizlet.quizletandroid.ui.navigationmanagers.e eVar3 = (com.quizlet.quizletandroid.ui.navigationmanagers.e) aVar;
                                eVar3.getClass();
                                Intrinsics.checkNotNullParameter(url2, "url");
                                Intrinsics.checkNotNullParameter(title2, "title");
                                String str2 = WebViewActivity.u;
                                eVar3.b(com.quizlet.features.setpage.utils.activities.a.a(eVar3.a, url2, title2));
                                break;
                        }
                        return Unit.a;
                    }
                };
                c0814p2.i0(objG);
            }
            final Function0 function0 = (Function0) objG;
            Object objG2 = Z.g(1653575597, c0814p2, false);
            if (objG2 == v) {
                final int i5 = 1;
                objG2 = new Function0() { // from class: com.quizlet.features.notes.detail.navigation.a
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        com.quizlet.features.notes.manager.a aVar = navigationManager;
                        Context context2 = context;
                        switch (i5) {
                            case 0:
                                Intrinsics.e(context2, "null cannot be cast to non-null type android.app.Activity");
                                Activity context3 = (Activity) context2;
                                ((com.quizlet.quizletandroid.ui.navigationmanagers.e) aVar).getClass();
                                Intrinsics.checkNotNullParameter(context3, "context");
                                context3.finish();
                                break;
                            case 1:
                                com.quizlet.quizletandroid.ui.navigationmanagers.e eVar = (com.quizlet.quizletandroid.ui.navigationmanagers.e) aVar;
                                eVar.getClass();
                                int i52 = UploadNotesActivity.i;
                                eVar.b(u.i(eVar.a, m2.a, null, null, null, 28));
                                Intrinsics.e(context2, "null cannot be cast to non-null type android.app.Activity");
                                Activity context4 = (Activity) context2;
                                eVar.getClass();
                                Intrinsics.checkNotNullParameter(context4, "context");
                                context4.finish();
                                break;
                            case 2:
                                String url = context2.getString(R.string.magic_notes_detail_help_center_url);
                                Intrinsics.checkNotNullExpressionValue(url, "getString(...)");
                                String title = context2.getString(R.string.user_settings_help_center);
                                Intrinsics.checkNotNullExpressionValue(title, "getString(...)");
                                com.quizlet.quizletandroid.ui.navigationmanagers.e eVar2 = (com.quizlet.quizletandroid.ui.navigationmanagers.e) aVar;
                                eVar2.getClass();
                                Intrinsics.checkNotNullParameter(url, "url");
                                Intrinsics.checkNotNullParameter(title, "title");
                                String str = WebViewActivity.u;
                                eVar2.b(com.quizlet.features.setpage.utils.activities.a.a(eVar2.a, url, title));
                                break;
                            default:
                                String url2 = context2.getString(R.string.magic_notes_detail_terms_of_service_url);
                                Intrinsics.checkNotNullExpressionValue(url2, "getString(...)");
                                String title2 = context2.getString(R.string.user_settings_terms_of_service);
                                Intrinsics.checkNotNullExpressionValue(title2, "getString(...)");
                                com.quizlet.quizletandroid.ui.navigationmanagers.e eVar3 = (com.quizlet.quizletandroid.ui.navigationmanagers.e) aVar;
                                eVar3.getClass();
                                Intrinsics.checkNotNullParameter(url2, "url");
                                Intrinsics.checkNotNullParameter(title2, "title");
                                String str2 = WebViewActivity.u;
                                eVar3.b(com.quizlet.features.setpage.utils.activities.a.a(eVar3.a, url2, title2));
                                break;
                        }
                        return Unit.a;
                    }
                };
                c0814p2.i0(objG2);
            }
            final Function0 function02 = (Function0) objG2;
            Object objG3 = Z.g(1653581989, c0814p2, false);
            if (objG3 == v) {
                objG3 = new C1280m(navigationManager, context, 20);
                c0814p2.i0(objG3);
            }
            final Function2 function22 = (Function2) objG3;
            Object objG4 = Z.g(1653590423, c0814p2, false);
            if (objG4 == v) {
                final int i6 = 2;
                objG4 = new Function0() { // from class: com.quizlet.features.notes.detail.navigation.a
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        com.quizlet.features.notes.manager.a aVar = navigationManager;
                        Context context2 = context;
                        switch (i6) {
                            case 0:
                                Intrinsics.e(context2, "null cannot be cast to non-null type android.app.Activity");
                                Activity context3 = (Activity) context2;
                                ((com.quizlet.quizletandroid.ui.navigationmanagers.e) aVar).getClass();
                                Intrinsics.checkNotNullParameter(context3, "context");
                                context3.finish();
                                break;
                            case 1:
                                com.quizlet.quizletandroid.ui.navigationmanagers.e eVar = (com.quizlet.quizletandroid.ui.navigationmanagers.e) aVar;
                                eVar.getClass();
                                int i52 = UploadNotesActivity.i;
                                eVar.b(u.i(eVar.a, m2.a, null, null, null, 28));
                                Intrinsics.e(context2, "null cannot be cast to non-null type android.app.Activity");
                                Activity context4 = (Activity) context2;
                                eVar.getClass();
                                Intrinsics.checkNotNullParameter(context4, "context");
                                context4.finish();
                                break;
                            case 2:
                                String url = context2.getString(R.string.magic_notes_detail_help_center_url);
                                Intrinsics.checkNotNullExpressionValue(url, "getString(...)");
                                String title = context2.getString(R.string.user_settings_help_center);
                                Intrinsics.checkNotNullExpressionValue(title, "getString(...)");
                                com.quizlet.quizletandroid.ui.navigationmanagers.e eVar2 = (com.quizlet.quizletandroid.ui.navigationmanagers.e) aVar;
                                eVar2.getClass();
                                Intrinsics.checkNotNullParameter(url, "url");
                                Intrinsics.checkNotNullParameter(title, "title");
                                String str = WebViewActivity.u;
                                eVar2.b(com.quizlet.features.setpage.utils.activities.a.a(eVar2.a, url, title));
                                break;
                            default:
                                String url2 = context2.getString(R.string.magic_notes_detail_terms_of_service_url);
                                Intrinsics.checkNotNullExpressionValue(url2, "getString(...)");
                                String title2 = context2.getString(R.string.user_settings_terms_of_service);
                                Intrinsics.checkNotNullExpressionValue(title2, "getString(...)");
                                com.quizlet.quizletandroid.ui.navigationmanagers.e eVar3 = (com.quizlet.quizletandroid.ui.navigationmanagers.e) aVar;
                                eVar3.getClass();
                                Intrinsics.checkNotNullParameter(url2, "url");
                                Intrinsics.checkNotNullParameter(title2, "title");
                                String str2 = WebViewActivity.u;
                                eVar3.b(com.quizlet.features.setpage.utils.activities.a.a(eVar3.a, url2, title2));
                                break;
                        }
                        return Unit.a;
                    }
                };
                c0814p2.i0(objG4);
            }
            final Function0 function03 = (Function0) objG4;
            Object objG5 = Z.g(1653599553, c0814p2, false);
            if (objG5 == v) {
                final int i7 = 3;
                objG5 = new Function0() { // from class: com.quizlet.features.notes.detail.navigation.a
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        com.quizlet.features.notes.manager.a aVar = navigationManager;
                        Context context2 = context;
                        switch (i7) {
                            case 0:
                                Intrinsics.e(context2, "null cannot be cast to non-null type android.app.Activity");
                                Activity context3 = (Activity) context2;
                                ((com.quizlet.quizletandroid.ui.navigationmanagers.e) aVar).getClass();
                                Intrinsics.checkNotNullParameter(context3, "context");
                                context3.finish();
                                break;
                            case 1:
                                com.quizlet.quizletandroid.ui.navigationmanagers.e eVar = (com.quizlet.quizletandroid.ui.navigationmanagers.e) aVar;
                                eVar.getClass();
                                int i52 = UploadNotesActivity.i;
                                eVar.b(u.i(eVar.a, m2.a, null, null, null, 28));
                                Intrinsics.e(context2, "null cannot be cast to non-null type android.app.Activity");
                                Activity context4 = (Activity) context2;
                                eVar.getClass();
                                Intrinsics.checkNotNullParameter(context4, "context");
                                context4.finish();
                                break;
                            case 2:
                                String url = context2.getString(R.string.magic_notes_detail_help_center_url);
                                Intrinsics.checkNotNullExpressionValue(url, "getString(...)");
                                String title = context2.getString(R.string.user_settings_help_center);
                                Intrinsics.checkNotNullExpressionValue(title, "getString(...)");
                                com.quizlet.quizletandroid.ui.navigationmanagers.e eVar2 = (com.quizlet.quizletandroid.ui.navigationmanagers.e) aVar;
                                eVar2.getClass();
                                Intrinsics.checkNotNullParameter(url, "url");
                                Intrinsics.checkNotNullParameter(title, "title");
                                String str = WebViewActivity.u;
                                eVar2.b(com.quizlet.features.setpage.utils.activities.a.a(eVar2.a, url, title));
                                break;
                            default:
                                String url2 = context2.getString(R.string.magic_notes_detail_terms_of_service_url);
                                Intrinsics.checkNotNullExpressionValue(url2, "getString(...)");
                                String title2 = context2.getString(R.string.user_settings_terms_of_service);
                                Intrinsics.checkNotNullExpressionValue(title2, "getString(...)");
                                com.quizlet.quizletandroid.ui.navigationmanagers.e eVar3 = (com.quizlet.quizletandroid.ui.navigationmanagers.e) aVar;
                                eVar3.getClass();
                                Intrinsics.checkNotNullParameter(url2, "url");
                                Intrinsics.checkNotNullParameter(title2, "title");
                                String str2 = WebViewActivity.u;
                                eVar3.b(com.quizlet.features.setpage.utils.activities.a.a(eVar3.a, url2, title2));
                                break;
                        }
                        return Unit.a;
                    }
                };
                c0814p2.i0(objG5);
            }
            final Function0 function04 = (Function0) objG5;
            c0814p2.p(false);
            c0814p2.X(1653613512);
            boolean zH = ((i2 & 896) == 256) | ((i2 & 14) == 4) | c0814p2.h(addMaterialFolderData) | ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32) | c0814p2.h(hD);
            Object objI2 = c0814p2.I();
            if (zH || objI2 == v) {
                final H h3 = hD;
                Function1 function1 = new Function1() { // from class: com.quizlet.features.notes.detail.navigation.b
                    @Override // kotlin.jvm.functions.Function1
                    public final Object invoke(Object obj) {
                        E NavHost = (E) obj;
                        Intrinsics.checkNotNullParameter(NavHost, "$this$NavHost");
                        i iVar = new i(magicNotesUuid, z, addMaterialFolderData);
                        Function0 function05 = function03;
                        Function0 function06 = function04;
                        com.quizlet.features.notes.manager.a aVar = navigationManager;
                        H h4 = h3;
                        N5.d(NavHost, iVar, new androidx.compose.runtime.internal.d(true, 851534086, new C4087l(aVar, h4, function0, function2, function02, function22, function05, function06)));
                        N5.d(NavHost, g.a, new androidx.compose.runtime.internal.d(true, 1192212527, new d(h4, 0)));
                        N5.e(NavHost, j.a, new androidx.compose.runtime.internal.d(true, 2146215723, new d(h4, 1)));
                        return Unit.a;
                    }
                };
                h2 = h3;
                c0814p2.i0(function1);
                objI2 = function1;
            } else {
                h2 = hD;
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            Q1.d(h2, "magic_notes", null, (Function1) objI2, c0814p, 48, 12);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.listitems.b(magicNotesUuid, navigationManager, z, addMaterialFolderData, h2, i);
        }
    }
}
