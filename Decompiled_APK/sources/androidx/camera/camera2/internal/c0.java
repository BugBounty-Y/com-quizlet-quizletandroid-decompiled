package androidx.camera.camera2.internal;

import android.R;
import android.content.Context;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.PorterDuff;
import android.graphics.Shader;
import android.graphics.SurfaceTexture;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.LayerDrawable;
import android.os.Build;
import android.os.Handler;
import android.util.Size;
import android.view.Menu;
import android.view.Surface;
import androidx.appcompat.widget.C0112u;
import androidx.appcompat.widget.N0;
import androidx.appcompat.widget.m1;
import androidx.camera.core.C0196t;
import androidx.collection.C0208f;
import androidx.lifecycle.C1247h;
import androidx.lifecycle.C1249j;
import androidx.lifecycle.C1259u;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.firebase.components.DependencyException;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.OTCallback;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.Response.OTResponse;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.quizletandroid.C4622e;
import com.quizlet.quizletandroid.C4624g;
import com.quizlet.quizletandroid.ui.startpage.nav2.RecommendationsActionOptionsFragment;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;

/* loaded from: classes.dex */
public final class c0 implements com.google.firebase.components.b, OTCallback, dagger.android.b {
    public final /* synthetic */ int a;
    public Object b;
    public Object c;
    public Object d;
    public Object e;
    public Object f;
    public Object g;

    public /* synthetic */ c0(int i, boolean z) {
        this.a = i;
    }

    public static void h(int i, Menu menu) {
        int i2;
        int iK = AbstractC0147y.k(i);
        int iK2 = AbstractC0147y.k(i);
        if (iK2 == 0) {
            i2 = R.string.copy;
        } else if (iK2 == 1) {
            i2 = R.string.paste;
        } else if (iK2 == 2) {
            i2 = R.string.cut;
        } else {
            if (iK2 != 3) {
                throw new NoWhenBranchMatchedException();
            }
            i2 = R.string.selectAll;
        }
        menu.add(0, iK, AbstractC0147y.k(i), i2).setShowAsAction(1);
    }

    public static void i(Menu menu, int i, Function0 function0) {
        if (function0 != null && menu.findItem(AbstractC0147y.k(i)) == null) {
            h(i, menu);
        } else {
            if (function0 != null || menu.findItem(AbstractC0147y.k(i)) == null) {
                return;
            }
            menu.removeItem(AbstractC0147y.k(i));
        }
    }

    public static boolean j(int[] iArr, int i) {
        for (int i2 : iArr) {
            if (i2 == i) {
                return true;
            }
        }
        return false;
    }

    public static ColorStateList l(Context context, int i) {
        int iC = m1.c(context, com.quizlet.quizletandroid.R.attr.colorControlHighlight);
        int iB = m1.b(context, com.quizlet.quizletandroid.R.attr.colorButtonNormal);
        int[] iArr = m1.b;
        int[] iArr2 = m1.d;
        int iB2 = androidx.core.graphics.d.b(iC, i);
        return new ColorStateList(new int[][]{iArr, iArr2, m1.c, m1.f}, new int[]{iB, iB2, androidx.core.graphics.d.b(iC, i), i});
    }

    public static LayerDrawable p(N0 n0, Context context, int i) throws Resources.NotFoundException {
        BitmapDrawable bitmapDrawable;
        BitmapDrawable bitmapDrawable2;
        BitmapDrawable bitmapDrawable3;
        int dimensionPixelSize = context.getResources().getDimensionPixelSize(i);
        Drawable drawableC = n0.c(context, com.quizlet.quizletandroid.R.drawable.abc_star_black_48dp);
        Drawable drawableC2 = n0.c(context, com.quizlet.quizletandroid.R.drawable.abc_star_half_black_48dp);
        if ((drawableC instanceof BitmapDrawable) && drawableC.getIntrinsicWidth() == dimensionPixelSize && drawableC.getIntrinsicHeight() == dimensionPixelSize) {
            bitmapDrawable = (BitmapDrawable) drawableC;
            bitmapDrawable2 = new BitmapDrawable(bitmapDrawable.getBitmap());
        } else {
            Bitmap bitmapCreateBitmap = Bitmap.createBitmap(dimensionPixelSize, dimensionPixelSize, Bitmap.Config.ARGB_8888);
            Canvas canvas = new Canvas(bitmapCreateBitmap);
            drawableC.setBounds(0, 0, dimensionPixelSize, dimensionPixelSize);
            drawableC.draw(canvas);
            bitmapDrawable = new BitmapDrawable(bitmapCreateBitmap);
            bitmapDrawable2 = new BitmapDrawable(bitmapCreateBitmap);
        }
        bitmapDrawable2.setTileModeX(Shader.TileMode.REPEAT);
        if ((drawableC2 instanceof BitmapDrawable) && drawableC2.getIntrinsicWidth() == dimensionPixelSize && drawableC2.getIntrinsicHeight() == dimensionPixelSize) {
            bitmapDrawable3 = (BitmapDrawable) drawableC2;
        } else {
            Bitmap bitmapCreateBitmap2 = Bitmap.createBitmap(dimensionPixelSize, dimensionPixelSize, Bitmap.Config.ARGB_8888);
            Canvas canvas2 = new Canvas(bitmapCreateBitmap2);
            drawableC2.setBounds(0, 0, dimensionPixelSize, dimensionPixelSize);
            drawableC2.draw(canvas2);
            bitmapDrawable3 = new BitmapDrawable(bitmapCreateBitmap2);
        }
        LayerDrawable layerDrawable = new LayerDrawable(new Drawable[]{bitmapDrawable, bitmapDrawable3, bitmapDrawable2});
        layerDrawable.setId(0, R.id.background);
        layerDrawable.setId(1, R.id.secondaryProgress);
        layerDrawable.setId(2, R.id.progress);
        return layerDrawable;
    }

    public static void s(Drawable drawable, int i, PorterDuff.Mode mode) {
        Drawable drawableMutate = drawable.mutate();
        if (mode == null) {
            mode = C0112u.b;
        }
        drawableMutate.setColorFilter(C0112u.c(i, mode));
    }

    @Override // com.google.firebase.components.b
    public com.google.firebase.inject.b a(com.google.firebase.components.q qVar) {
        if (((Set) this.c).contains(qVar)) {
            return ((com.google.firebase.components.b) this.g).a(qVar);
        }
        throw new DependencyException("Attempting to request an undeclared dependency Provider<" + qVar + ">.");
    }

    @Override // com.google.firebase.components.b
    public com.google.firebase.inject.b b(Class cls) {
        return a(com.google.firebase.components.q.a(cls));
    }

    @Override // com.google.firebase.components.b
    public Set c(com.google.firebase.components.q qVar) {
        if (((Set) this.e).contains(qVar)) {
            return ((com.google.firebase.components.b) this.g).c(qVar);
        }
        throw new DependencyException("Attempting to request an undeclared dependency Set<" + qVar + ">.");
    }

    @Override // dagger.android.b
    public void d(Object obj) {
        RecommendationsActionOptionsFragment recommendationsActionOptionsFragment = (RecommendationsActionOptionsFragment) obj;
        C4622e c4622e = (C4622e) this.f;
        recommendationsActionOptionsFragment.q = c4622e.a();
        com.quizlet.quizletandroid.u uVar = (com.quizlet.quizletandroid.u) this.d;
        recommendationsActionOptionsFragment.z = (com.quizlet.quizletandroid.util.a) uVar.y1.get();
        recommendationsActionOptionsFragment.A = new com.onetrust.otpublishers.headless.UI.viewmodel.c(com.google.common.collect.m.b(com.quizlet.quizletandroid.ui.joincontenttofolder.k.class, uVar.e1, com.quizlet.quizletandroid.ui.startpage.nav2.Y.class, ((C4624g) this.e).g, com.quizlet.quizletandroid.ui.learnpaywall.k.class, c4622e.U, com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.N.class, (com.quizlet.quizletandroid.n) this.g));
    }

    @Override // com.google.firebase.components.b
    public com.google.firebase.inject.b e(com.google.firebase.components.q qVar) {
        if (((Set) this.f).contains(qVar)) {
            return ((com.google.firebase.components.b) this.g).e(qVar);
        }
        throw new DependencyException("Attempting to request an undeclared dependency Provider<Set<" + qVar + ">>.");
    }

    @Override // com.google.firebase.components.b
    public Object f(com.google.firebase.components.q qVar) {
        if (((Set) this.b).contains(qVar)) {
            return ((com.google.firebase.components.b) this.g).f(qVar);
        }
        throw new DependencyException("Attempting to request an undeclared dependency " + qVar + ".");
    }

    @Override // com.google.firebase.components.b
    public com.google.firebase.components.o g(com.google.firebase.components.q qVar) {
        if (((Set) this.d).contains(qVar)) {
            return ((com.google.firebase.components.b) this.g).g(qVar);
        }
        throw new DependencyException("Attempting to request an undeclared dependency Deferred<" + qVar + ">.");
    }

    @Override // com.google.firebase.components.b
    public Object get(Class cls) {
        if (!((Set) this.b).contains(com.google.firebase.components.q.a(cls))) {
            throw new DependencyException("Attempting to request an undeclared dependency " + cls + ".");
        }
        Object obj = ((com.google.firebase.components.b) this.g).get(cls);
        if (!cls.equals(com.google.firebase.events.b.class)) {
            return obj;
        }
        return new com.google.firebase.components.r();
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object k(kotlin.coroutines.jvm.internal.c r6) throws java.lang.Throwable {
        /*
            r5 = this;
            boolean r0 = r6 instanceof com.quizlet.quizletandroid.ui.f
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.quizletandroid.ui.f r0 = (com.quizlet.quizletandroid.ui.f) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.ui.f r0 = new com.quizlet.quizletandroid.ui.f
            r0.<init>(r5, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 0
            r4 = 1
            if (r2 == 0) goto L32
            if (r2 != r4) goto L2a
            androidx.camera.camera2.internal.c0 r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L4a
        L2a:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L32:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            com.quizlet.quizletandroid.ui.g r6 = new com.quizlet.quizletandroid.ui.g
            r6.<init>(r5, r3)
            r0.j = r5
            r0.m = r4
            java.lang.Object r2 = r5.f
            kotlinx.coroutines.y r2 = (kotlinx.coroutines.AbstractC5040y) r2
            java.lang.Object r6 = kotlinx.coroutines.E.J(r2, r6, r0)
            if (r6 != r1) goto L49
            return r1
        L49:
            r0 = r5
        L4a:
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            boolean r6 = r6.booleanValue()
            java.lang.String r1 = "rootView"
            if (r6 == 0) goto L70
            java.lang.Object r6 = r0.g
            com.quizlet.quizletandroid.ui.RootActivity r6 = (com.quizlet.quizletandroid.ui.RootActivity) r6
            if (r6 == 0) goto L6c
            java.lang.String r0 = com.quizlet.features.emailconfirmation.ui.activities.MagicLinkConfirmationActivity.r
            java.lang.String r0 = "context"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r0)
            android.content.Intent r0 = new android.content.Intent
            java.lang.Class<com.quizlet.features.emailconfirmation.ui.activities.MagicLinkConfirmationActivity> r1 = com.quizlet.features.emailconfirmation.ui.activities.MagicLinkConfirmationActivity.class
            r0.<init>(r6, r1)
            r6.startActivity(r0)
            goto L79
        L6c:
            kotlin.jvm.internal.Intrinsics.m(r1)
            throw r3
        L70:
            java.lang.Object r6 = r0.g
            com.quizlet.quizletandroid.ui.RootActivity r6 = (com.quizlet.quizletandroid.ui.RootActivity) r6
            if (r6 == 0) goto L7c
            r6.y()
        L79:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        L7c:
            kotlin.jvm.internal.Intrinsics.m(r1)
            throw r3
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.camera.camera2.internal.c0.k(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public androidx.camera.core.impl.q0 m() {
        SurfaceTexture surfaceTexture = new SurfaceTexture(0);
        Size size = (Size) this.e;
        surfaceTexture.setDefaultBufferSize(size.getWidth(), size.getHeight());
        Surface surface = new Surface(surfaceTexture);
        androidx.camera.core.impl.m0 m0VarD = androidx.camera.core.impl.m0.d((b0) this.d, size);
        m0VarD.b.a = 1;
        androidx.camera.core.g0 g0Var = new androidx.camera.core.g0(surface);
        this.b = g0Var;
        com.google.common.util.concurrent.e eVarD = androidx.camera.core.impl.utils.futures.i.d(g0Var.e);
        com.quizlet.data.repository.qclass.c cVar = new com.quizlet.data.repository.qclass.c(1, surface, surfaceTexture);
        eVarD.a(new androidx.camera.core.impl.utils.futures.h(0, eVarD, cVar), com.google.android.gms.internal.mlkit_vision_barcode.T.a());
        m0VarD.b((androidx.camera.core.g0) this.b, C0196t.d, -1);
        androidx.camera.core.impl.n0 n0Var = (androidx.camera.core.impl.n0) this.g;
        if (n0Var != null) {
            n0Var.b();
        }
        androidx.camera.core.impl.n0 n0Var2 = new androidx.camera.core.impl.n0(new Z(this, 0));
        this.g = n0Var2;
        m0VarD.f = n0Var2;
        return m0VarD.c();
    }

    public ArrayList n() {
        ArrayList arrayList;
        synchronized (this.c) {
            arrayList = new ArrayList((LinkedHashSet) this.d);
        }
        return arrayList;
    }

    public com.google.firebase.components.o o(Class cls) {
        return g(com.google.firebase.components.q.a(cls));
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTCallback
    public void onFailure(OTResponse oTResponse) {
        com.onetrust.otpublishers.headless.Internal.Network.d dVar = (com.onetrust.otpublishers.headless.Internal.Network.d) this.g;
        String str = dVar.b;
        androidx.work.impl.model.c cVar = (androidx.work.impl.model.c) this.e;
        OTLogger.c("NetworkRequestHandler", 4, "Requesting OTT data from : " + str);
        OTLogger.c("NetworkRequestHandler", 4, " OTT data Download : Download OTT data started");
        ((com.onetrust.otpublishers.headless.Internal.Network.a) this.c).b(str).j(new com.quizlet.data.repository.progress.b(dVar, (String) this.d, cVar, (OTPublishersHeadlessSDK) this.f));
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTCallback
    public void onSuccess(OTResponse oTResponse) {
        ((OTCallback) this.b).onSuccess(oTResponse);
    }

    public ArrayList q() {
        ArrayList arrayList;
        ArrayList arrayList2;
        synchronized (this.c) {
            arrayList = new ArrayList();
            arrayList.addAll(n());
            synchronized (this.c) {
                arrayList2 = new ArrayList((LinkedHashSet) this.f);
            }
            arrayList.addAll(arrayList2);
        }
        return arrayList;
    }

    public ColorStateList r(Context context, int i) {
        if (i == com.quizlet.quizletandroid.R.drawable.abc_edit_text_material) {
            return androidx.core.content.c.c(context, com.quizlet.quizletandroid.R.color.abc_tint_edittext);
        }
        if (i == 2131230834) {
            return androidx.core.content.c.c(context, com.quizlet.quizletandroid.R.color.abc_tint_switch_track);
        }
        if (i != com.quizlet.quizletandroid.R.drawable.abc_switch_thumb_material) {
            if (i == com.quizlet.quizletandroid.R.drawable.abc_btn_default_mtrl_shape) {
                return l(context, m1.c(context, com.quizlet.quizletandroid.R.attr.colorButtonNormal));
            }
            if (i == com.quizlet.quizletandroid.R.drawable.abc_btn_borderless_material) {
                return l(context, 0);
            }
            if (i == com.quizlet.quizletandroid.R.drawable.abc_btn_colored_material) {
                return l(context, m1.c(context, com.quizlet.quizletandroid.R.attr.colorAccent));
            }
            if (i == 2131230829 || i == com.quizlet.quizletandroid.R.drawable.abc_spinner_textfield_background_material) {
                return androidx.core.content.c.c(context, com.quizlet.quizletandroid.R.color.abc_tint_spinner);
            }
            if (j((int[]) this.c, i)) {
                return m1.d(context, com.quizlet.quizletandroid.R.attr.colorControlNormal);
            }
            if (j((int[]) this.f, i)) {
                return androidx.core.content.c.c(context, com.quizlet.quizletandroid.R.color.abc_tint_default);
            }
            if (j((int[]) this.g, i)) {
                return androidx.core.content.c.c(context, com.quizlet.quizletandroid.R.color.abc_tint_btn_checkable);
            }
            if (i == com.quizlet.quizletandroid.R.drawable.abc_seekbar_thumb_material) {
                return androidx.core.content.c.c(context, com.quizlet.quizletandroid.R.color.abc_tint_seek_thumb);
            }
            return null;
        }
        int[][] iArr = new int[3][];
        int[] iArr2 = new int[3];
        ColorStateList colorStateListD = m1.d(context, com.quizlet.quizletandroid.R.attr.colorSwitchThumbNormal);
        if (colorStateListD == null || !colorStateListD.isStateful()) {
            iArr[0] = m1.b;
            iArr2[0] = m1.b(context, com.quizlet.quizletandroid.R.attr.colorSwitchThumbNormal);
            iArr[1] = m1.e;
            iArr2[1] = m1.c(context, com.quizlet.quizletandroid.R.attr.colorControlActivated);
            iArr[2] = m1.f;
            iArr2[2] = m1.c(context, com.quizlet.quizletandroid.R.attr.colorSwitchThumbNormal);
        } else {
            int[] iArr3 = m1.b;
            iArr[0] = iArr3;
            iArr2[0] = colorStateListD.getColorForState(iArr3, 0);
            iArr[1] = m1.e;
            iArr2[1] = m1.c(context, com.quizlet.quizletandroid.R.attr.colorControlActivated);
            iArr[2] = m1.f;
            iArr2[2] = colorStateListD.getDefaultColor();
        }
        return new ColorStateList(iArr, iArr2);
    }

    public String toString() {
        switch (this.a) {
            case 13:
                StringBuilder sb = new StringBuilder("CloseButtonProperty{textColor='");
                sb.append((String) this.b);
                sb.append("', text='");
                sb.append((String) this.c);
                sb.append("', showText='");
                sb.append((String) this.d);
                sb.append("', showCloseButton='");
                sb.append((String) this.e);
                sb.append("', closeButtonColor='");
                return android.support.v4.media.session.a.t(sb, (String) this.f, "'}");
            case 14:
                StringBuilder sb2 = new StringBuilder("TextProperty{menuColor=");
                sb2.append((String) this.b);
                sb2.append(", menuTextColor='");
                sb2.append((String) this.c);
                sb2.append("', focusColor='");
                sb2.append((String) this.d);
                sb2.append("', focusTextColor='");
                sb2.append((String) this.e);
                sb2.append("', activeColor='");
                sb2.append((String) this.f);
                sb2.append("', activeTextColor='");
                return android.support.v4.media.session.a.t(sb2, (String) this.g, "'}");
            default:
                return super.toString();
        }
    }

    public c0(com.onetrust.otpublishers.headless.Internal.Network.d dVar, OTCallback oTCallback, com.onetrust.otpublishers.headless.Internal.Network.a aVar, String str, androidx.work.impl.model.c cVar, OTPublishersHeadlessSDK oTPublishersHeadlessSDK) {
        this.a = 12;
        this.g = dVar;
        this.b = oTCallback;
        this.c = aVar;
        this.d = str;
        this.e = cVar;
        this.f = oTPublishersHeadlessSDK;
    }

    public c0(Context context, String str) {
        String strConcat;
        this.a = 6;
        this.b = context.getApplicationContext();
        this.c = str;
        this.d = new TreeMap();
        String packageName = context.getPackageName();
        try {
            strConcat = packageName + "-" + com.google.android.gms.common.wrappers.c.a(context).c(context.getPackageName(), 0).versionName;
        } catch (PackageManager.NameNotFoundException e) {
            com.google.android.gms.ads.internal.util.client.i.f("Unable to get package version name for reporting", e);
            strConcat = String.valueOf(packageName).concat("-missing");
        }
        this.g = strConcat;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r3v3, types: [java.util.Map] */
    public c0(Set set, C0208f c0208f, String str, String str2, com.google.android.gms.signin.a aVar) {
        this.a = 7;
        Set setUnmodifiableSet = set == null ? Collections.EMPTY_SET : Collections.unmodifiableSet(set);
        this.b = setUnmodifiableSet;
        C0208f c0208f2 = c0208f == null ? Collections.EMPTY_MAP : c0208f;
        this.d = str;
        this.e = str2;
        this.f = aVar == null ? com.google.android.gms.signin.a.a : aVar;
        HashSet hashSet = new HashSet(setUnmodifiableSet);
        Iterator it2 = c0208f2.values().iterator();
        if (!it2.hasNext()) {
            this.c = Collections.unmodifiableSet(hashSet);
            return;
        }
        throw android.support.v4.media.session.a.d(it2);
    }

    public c0(com.google.firebase.crashlytics.internal.settings.b getPracticeTestDetailUseCase, com.quizlet.data.repository.activitycenter.b getPracticeTestPastExamsUseCase, com.google.firebase.heartbeatinfo.e getDefaultPracticeTestConfigurationUseCase, com.google.mlkit.common.internal.model.a getSupportedQuestionFormatsUseCase, androidx.work.impl.model.e userHasFreeTrialUseCase, UserInfoCache userInfoCache) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(getPracticeTestDetailUseCase, "getPracticeTestDetailUseCase");
        Intrinsics.checkNotNullParameter(getPracticeTestPastExamsUseCase, "getPracticeTestPastExamsUseCase");
        Intrinsics.checkNotNullParameter(getDefaultPracticeTestConfigurationUseCase, "getDefaultPracticeTestConfigurationUseCase");
        Intrinsics.checkNotNullParameter(getSupportedQuestionFormatsUseCase, "getSupportedQuestionFormatsUseCase");
        Intrinsics.checkNotNullParameter(userHasFreeTrialUseCase, "userHasFreeTrialUseCase");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        this.b = getPracticeTestDetailUseCase;
        this.c = getPracticeTestPastExamsUseCase;
        this.d = getDefaultPracticeTestConfigurationUseCase;
        this.e = getSupportedQuestionFormatsUseCase;
        this.f = userHasFreeTrialUseCase;
        this.g = userInfoCache;
    }

    public c0(com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager, EventLogger eventLogger, com.quizlet.analytics.marketing.appsflyer.b marketingAnalyticsDeepLinking, com.lyft.android.scissors.b getCurrentConfirmationWallEmailUseCase, AbstractC5040y ioDispatcher) {
        this.a = 17;
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        Intrinsics.checkNotNullParameter(marketingAnalyticsDeepLinking, "marketingAnalyticsDeepLinking");
        Intrinsics.checkNotNullParameter(getCurrentConfirmationWallEmailUseCase, "getCurrentConfirmationWallEmailUseCase");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.b = loggedInUserManager;
        this.c = eventLogger;
        this.d = marketingAnalyticsDeepLinking;
        this.e = getCurrentConfirmationWallEmailUseCase;
        this.f = ioDispatcher;
    }

    public c0(androidx.compose.ui.input.nestedscroll.b bVar) {
        this.a = 4;
        androidx.compose.ui.geometry.c cVar = androidx.compose.ui.geometry.c.e;
        this.b = bVar;
        this.c = cVar;
        this.d = null;
        this.e = null;
        this.f = null;
        this.g = null;
    }

    public c0(com.google.firebase.components.a aVar, com.google.firebase.components.b bVar) {
        this.a = 11;
        HashSet hashSet = new HashSet();
        HashSet hashSet2 = new HashSet();
        HashSet hashSet3 = new HashSet();
        HashSet hashSet4 = new HashSet();
        HashSet hashSet5 = new HashSet();
        for (com.google.firebase.components.j jVar : aVar.c) {
            int i = jVar.c;
            boolean z = i == 0;
            int i2 = jVar.b;
            com.google.firebase.components.q qVar = jVar.a;
            if (z) {
                if (i2 == 2) {
                    hashSet4.add(qVar);
                } else {
                    hashSet.add(qVar);
                }
            } else if (i == 2) {
                hashSet3.add(qVar);
            } else if (i2 == 2) {
                hashSet5.add(qVar);
            } else {
                hashSet2.add(qVar);
            }
        }
        if (!aVar.g.isEmpty()) {
            hashSet.add(com.google.firebase.components.q.a(com.google.firebase.events.b.class));
        }
        this.b = Collections.unmodifiableSet(hashSet);
        this.c = Collections.unmodifiableSet(hashSet2);
        this.d = Collections.unmodifiableSet(hashSet3);
        this.e = Collections.unmodifiableSet(hashSet4);
        this.f = Collections.unmodifiableSet(hashSet5);
        this.g = bVar;
    }

    public c0(androidx.camera.core.impl.utils.executor.k kVar) {
        this.a = 2;
        this.c = new Object();
        this.d = new LinkedHashSet();
        this.e = new LinkedHashSet();
        this.f = new LinkedHashSet();
        this.g = new N(this);
        this.b = kVar;
    }

    public c0(int i) {
        this.a = i;
        switch (i) {
            case 13:
                this.g = new androidx.constraintlayout.motion.widget.n();
                break;
            default:
                this.b = new int[]{2131230844, 2131230842, 2131230768};
                this.c = new int[]{2131230792, com.quizlet.quizletandroid.R.drawable.abc_seekbar_tick_mark_material, com.quizlet.quizletandroid.R.drawable.abc_ic_menu_share_mtrl_alpha, com.quizlet.quizletandroid.R.drawable.abc_ic_menu_copy_mtrl_am_alpha, com.quizlet.quizletandroid.R.drawable.abc_ic_menu_cut_mtrl_alpha, com.quizlet.quizletandroid.R.drawable.abc_ic_menu_selectall_mtrl_alpha, com.quizlet.quizletandroid.R.drawable.abc_ic_menu_paste_mtrl_am_alpha};
                this.d = new int[]{2131230841, 2131230843, 2131230785, com.quizlet.quizletandroid.R.drawable.abc_text_cursor_material, 2131230838, 2131230839, 2131230840};
                this.e = new int[]{2131230817, com.quizlet.quizletandroid.R.drawable.abc_cab_background_internal_bg, 2131230816};
                this.f = new int[]{com.quizlet.quizletandroid.R.drawable.abc_tab_indicator_material, com.quizlet.quizletandroid.R.drawable.abc_textfield_search_material};
                this.g = new int[]{com.quizlet.quizletandroid.R.drawable.abc_btn_check_material, com.quizlet.quizletandroid.R.drawable.abc_btn_radio_material, com.quizlet.quizletandroid.R.drawable.abc_btn_check_material_anim, com.quizlet.quizletandroid.R.drawable.abc_btn_radio_material_anim};
                break;
        }
    }

    public c0(androidx.camera.camera2.internal.compat.k kVar, W w, C0139p c0139p) {
        Size size;
        this.a = 0;
        androidx.camera.camera2.internal.compat.workaround.f fVar = new androidx.camera.camera2.internal.compat.workaround.f();
        Size size2 = null;
        this.g = null;
        this.d = new b0();
        this.f = c0139p;
        Size[] sizeArrP = kVar.b().p(34);
        if (sizeArrP == null) {
            AbstractC3053s1.c("MeteringRepeating", "Can not get output size list.");
            size = new Size(0, 0);
        } else {
            if (fVar.a != null && "Huawei".equalsIgnoreCase(Build.BRAND) && "mha-l29".equalsIgnoreCase(Build.MODEL)) {
                ArrayList arrayList = new ArrayList();
                for (Size size3 : sizeArrP) {
                    if (androidx.camera.camera2.internal.compat.workaround.f.c.compare(size3, androidx.camera.camera2.internal.compat.workaround.f.b) >= 0) {
                        arrayList.add(size3);
                    }
                }
                sizeArrP = (Size[]) arrayList.toArray(new Size[0]);
            }
            List listAsList = Arrays.asList(sizeArrP);
            Collections.sort(listAsList, new a0(0));
            Size sizeE = w.e();
            long jMin = Math.min(sizeE.getWidth() * sizeE.getHeight(), 307200L);
            int length = sizeArrP.length;
            int i = 0;
            while (true) {
                if (i >= length) {
                    break;
                }
                Size size4 = sizeArrP[i];
                long width = size4.getWidth() * size4.getHeight();
                if (width == jMin) {
                    size = size4;
                    break;
                } else if (width <= jMin) {
                    i++;
                    size2 = size4;
                } else if (size2 != null) {
                    size = size2;
                }
            }
            size = (Size) listAsList.get(0);
        }
        this.e = size;
        Objects.toString(size);
        AbstractC3053s1.f(3, "MeteringRepeating");
        this.c = m();
    }

    public c0(C1249j liveData, C1259u block, kotlinx.coroutines.internal.d scope, C1247h onDone) {
        this.a = 5;
        Intrinsics.checkNotNullParameter(liveData, "liveData");
        Intrinsics.checkNotNullParameter(block, "block");
        Intrinsics.checkNotNullParameter(scope, "scope");
        Intrinsics.checkNotNullParameter(onDone, "onDone");
        this.b = liveData;
        this.c = block;
        this.d = scope;
        this.e = onDone;
    }

    public c0(Handler handler, c0 c0Var, androidx.camera.core.impl.i0 i0Var, androidx.camera.core.impl.i0 i0Var2, androidx.camera.core.impl.utils.executor.e eVar, androidx.camera.core.impl.utils.executor.k kVar) {
        this.a = 3;
        this.b = kVar;
        this.c = eVar;
        this.d = handler;
        this.e = c0Var;
        this.f = i0Var;
        this.g = i0Var2;
    }

    public c0(okhttp3.internal.concurrent.d taskRunner) {
        this.a = 18;
        Intrinsics.checkNotNullParameter(taskRunner, "taskRunner");
        this.b = taskRunner;
        this.g = okhttp3.internal.http2.g.a;
    }

    public c0(com.quizlet.quizletandroid.u uVar, C4624g c4624g, C4622e c4622e, Long l, Integer num) {
        this.a = 16;
        this.d = uVar;
        this.e = c4624g;
        this.f = c4622e;
        this.b = l;
        this.c = num;
        this.g = new com.quizlet.quizletandroid.n(uVar, this);
    }
}
