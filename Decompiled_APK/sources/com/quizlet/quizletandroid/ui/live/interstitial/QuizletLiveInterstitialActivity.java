package com.quizlet.quizletandroid.ui.live.interstitial;

import android.app.Activity;
import android.content.ComponentCallbacks2;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import androidx.activity.v;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3188k6;
import com.google.android.gms.internal.mlkit_vision_barcode.N6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3699p6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.M5;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.assembly.widgets.buttons.AssemblyTextButton;
import com.quizlet.baseui.base.f;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.N;
import com.quizlet.quizletandroid.ui.group.i;
import com.quizlet.quizletandroid.ui.qrcodes.QLiveQrCodeReaderActivity;
import io.reactivex.rxjava3.internal.observers.e;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class QuizletLiveInterstitialActivity extends f implements d, dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public static final /* synthetic */ int q = 0;
    public com.quizlet.login.authentication.login.a l;
    public volatile dagger.hilt.android.internal.managers.b m;
    public final Object n = new Object();
    public boolean o = false;
    public com.quizlet.data.repository.classmembership.c p;

    public QuizletLiveInterstitialActivity() {
        addOnContextAvailableListener(new i(this, 5));
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        String name = QuizletLiveInterstitialActivity.class.getName();
        Intrinsics.checkNotNullExpressionValue(name, "getName(...)");
        return name;
    }

    @Override // com.quizlet.baseui.base.f
    public final androidx.viewbinding.a N() {
        View viewInflate = getLayoutInflater().inflate(R.layout.live_interstitial_activity, (ViewGroup) null, false);
        int i = R.id.btnJoinGame;
        AssemblyPrimaryButton assemblyPrimaryButton = (AssemblyPrimaryButton) AbstractC3375o2.c(R.id.btnJoinGame, viewInflate);
        if (assemblyPrimaryButton != null) {
            i = R.id.btnSecondaryAction;
            AssemblyTextButton assemblyTextButton = (AssemblyTextButton) AbstractC3375o2.c(R.id.btnSecondaryAction, viewInflate);
            if (assemblyTextButton != null) {
                i = R.id.closeLiveInterstitial;
                FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.closeLiveInterstitial, viewInflate);
                if (frameLayout != null) {
                    i = R.id.groupImage;
                    ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.groupImage, viewInflate);
                    if (imageView != null) {
                        i = R.id.interstitialHeader;
                        QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.interstitialHeader, viewInflate);
                        if (qTextView != null) {
                            i = R.id.interstitialSubText;
                            QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.interstitialSubText, viewInflate);
                            if (qTextView2 != null) {
                                i = R.id.welcomeText;
                                if (((QTextView) AbstractC3375o2.c(R.id.welcomeText, viewInflate)) != null) {
                                    N n = new N((ConstraintLayout) viewInflate, assemblyPrimaryButton, assemblyTextButton, frameLayout, imageView, qTextView, qTextView2);
                                    Intrinsics.checkNotNullExpressionValue(n, "inflate(...)");
                                    return n;
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final dagger.hilt.android.internal.managers.b O() {
        if (this.m == null) {
            synchronized (this.n) {
                try {
                    if (this.m == null) {
                        this.m = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.m;
    }

    public final com.quizlet.data.repository.classmembership.c P() {
        com.quizlet.data.repository.classmembership.c cVar = this.p;
        if (cVar != null) {
            return cVar;
        }
        Intrinsics.m("presenter");
        throw null;
    }

    public final void Q(Bundle bundle) {
        super.onCreate(bundle);
        if (getApplication() instanceof dagger.hilt.internal.b) {
            com.quizlet.login.authentication.login.a aVarB = O().b();
            this.l = aVarB;
            if (aVarB.l()) {
                this.l.b = getDefaultViewModelCreationExtras();
            }
        }
    }

    public final void R() {
        super.onDestroy();
        com.quizlet.login.authentication.login.a aVar = this.l;
        if (aVar != null) {
            aVar.b = null;
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        return O().d();
    }

    @Override // androidx.activity.s, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        ComponentCallbacks2 componentCallbacks2B = N6.b(getApplicationContext());
        return (!(componentCallbacks2B instanceof dagger.hilt.internal.b) || ((componentCallbacks2B instanceof dagger.hilt.android.internal.migration.a) && !((dagger.hilt.android.internal.migration.a) componentCallbacks2B).u())) ? super.getDefaultViewModelProviderFactory() : P6.a(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, android.app.Activity
    public final void onActivityResult(int i, int i2, Intent intent) {
        super.onActivityResult(i, i2, intent);
        if (i == 1) {
            setResult(i2, intent);
            finish();
        }
    }

    @Override // com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        Q(bundle);
        v.b(this, null, 3);
        ConstraintLayout constraintLayout = ((N) K()).a;
        Intrinsics.checkNotNullExpressionValue(constraintLayout, "getRoot(...)");
        AbstractC3188k6.a(constraintLayout);
        AbstractC3699p6.b(this, R.attr.SysColorCard);
        com.quizlet.data.repository.classmembership.c cVarP = P();
        Intrinsics.checkNotNullParameter(this, "view");
        Intrinsics.checkNotNullParameter(this, "<set-?>");
        cVarP.d = this;
        com.quizlet.data.repository.classmembership.c cVarP2 = P();
        e disposable = ((com.quizlet.infra.legacysyncengine.managers.d) cVarP2.a).a().i(new c(cVarP2, 1), io.reactivex.rxjava3.internal.functions.d.e);
        Intrinsics.checkNotNullExpressionValue(disposable, "subscribe(...)");
        io.reactivex.rxjava3.disposables.a plusAssign = (io.reactivex.rxjava3.disposables.a) cVarP2.c;
        Intrinsics.checkNotNullParameter(plusAssign, "$this$plusAssign");
        Intrinsics.checkNotNullParameter(disposable, "disposable");
        plusAssign.b(disposable);
        FrameLayout closeLiveInterstitial = ((N) K()).d;
        Intrinsics.checkNotNullExpressionValue(closeLiveInterstitial, "closeLiveInterstitial");
        final int i = 0;
        closeLiveInterstitial.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.live.interstitial.a
            public final /* synthetic */ QuizletLiveInterstitialActivity b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                QuizletLiveInterstitialActivity quizletLiveInterstitialActivity = this.b;
                switch (i) {
                    case 0:
                        int i2 = QuizletLiveInterstitialActivity.q;
                        QuizletLiveInterstitialActivity quizletLiveInterstitialActivity2 = (QuizletLiveInterstitialActivity) quizletLiveInterstitialActivity.P().c();
                        com.quizlet.live.a aVar = com.quizlet.live.a.a;
                        quizletLiveInterstitialActivity2.setResult(-3);
                        quizletLiveInterstitialActivity2.finish();
                        break;
                    case 1:
                        int i3 = QuizletLiveInterstitialActivity.q;
                        QuizletLiveInterstitialActivity quizletLiveInterstitialActivity3 = (QuizletLiveInterstitialActivity) quizletLiveInterstitialActivity.P().c();
                        String str = QLiveQrCodeReaderActivity.t;
                        quizletLiveInterstitialActivity3.startActivityForResult(M5.b(quizletLiveInterstitialActivity3), 1);
                        break;
                    default:
                        int i4 = QuizletLiveInterstitialActivity.q;
                        com.quizlet.data.repository.classmembership.c cVarP3 = quizletLiveInterstitialActivity.P();
                        e disposable2 = ((com.quizlet.infra.legacysyncengine.managers.d) cVarP3.a).a().i(new c(cVarP3, 0), io.reactivex.rxjava3.internal.functions.d.e);
                        Intrinsics.checkNotNullExpressionValue(disposable2, "subscribe(...)");
                        io.reactivex.rxjava3.disposables.a plusAssign2 = (io.reactivex.rxjava3.disposables.a) cVarP3.c;
                        Intrinsics.checkNotNullParameter(plusAssign2, "$this$plusAssign");
                        Intrinsics.checkNotNullParameter(disposable2, "disposable");
                        plusAssign2.b(disposable2);
                        break;
                }
            }
        });
        AssemblyPrimaryButton btnJoinGame = ((N) K()).b;
        Intrinsics.checkNotNullExpressionValue(btnJoinGame, "btnJoinGame");
        final int i2 = 1;
        btnJoinGame.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.live.interstitial.a
            public final /* synthetic */ QuizletLiveInterstitialActivity b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                QuizletLiveInterstitialActivity quizletLiveInterstitialActivity = this.b;
                switch (i2) {
                    case 0:
                        int i22 = QuizletLiveInterstitialActivity.q;
                        QuizletLiveInterstitialActivity quizletLiveInterstitialActivity2 = (QuizletLiveInterstitialActivity) quizletLiveInterstitialActivity.P().c();
                        com.quizlet.live.a aVar = com.quizlet.live.a.a;
                        quizletLiveInterstitialActivity2.setResult(-3);
                        quizletLiveInterstitialActivity2.finish();
                        break;
                    case 1:
                        int i3 = QuizletLiveInterstitialActivity.q;
                        QuizletLiveInterstitialActivity quizletLiveInterstitialActivity3 = (QuizletLiveInterstitialActivity) quizletLiveInterstitialActivity.P().c();
                        String str = QLiveQrCodeReaderActivity.t;
                        quizletLiveInterstitialActivity3.startActivityForResult(M5.b(quizletLiveInterstitialActivity3), 1);
                        break;
                    default:
                        int i4 = QuizletLiveInterstitialActivity.q;
                        com.quizlet.data.repository.classmembership.c cVarP3 = quizletLiveInterstitialActivity.P();
                        e disposable2 = ((com.quizlet.infra.legacysyncengine.managers.d) cVarP3.a).a().i(new c(cVarP3, 0), io.reactivex.rxjava3.internal.functions.d.e);
                        Intrinsics.checkNotNullExpressionValue(disposable2, "subscribe(...)");
                        io.reactivex.rxjava3.disposables.a plusAssign2 = (io.reactivex.rxjava3.disposables.a) cVarP3.c;
                        Intrinsics.checkNotNullParameter(plusAssign2, "$this$plusAssign");
                        Intrinsics.checkNotNullParameter(disposable2, "disposable");
                        plusAssign2.b(disposable2);
                        break;
                }
            }
        });
        AssemblyTextButton btnSecondaryAction = ((N) K()).c;
        Intrinsics.checkNotNullExpressionValue(btnSecondaryAction, "btnSecondaryAction");
        final int i3 = 2;
        btnSecondaryAction.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.live.interstitial.a
            public final /* synthetic */ QuizletLiveInterstitialActivity b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                QuizletLiveInterstitialActivity quizletLiveInterstitialActivity = this.b;
                switch (i3) {
                    case 0:
                        int i22 = QuizletLiveInterstitialActivity.q;
                        QuizletLiveInterstitialActivity quizletLiveInterstitialActivity2 = (QuizletLiveInterstitialActivity) quizletLiveInterstitialActivity.P().c();
                        com.quizlet.live.a aVar = com.quizlet.live.a.a;
                        quizletLiveInterstitialActivity2.setResult(-3);
                        quizletLiveInterstitialActivity2.finish();
                        break;
                    case 1:
                        int i32 = QuizletLiveInterstitialActivity.q;
                        QuizletLiveInterstitialActivity quizletLiveInterstitialActivity3 = (QuizletLiveInterstitialActivity) quizletLiveInterstitialActivity.P().c();
                        String str = QLiveQrCodeReaderActivity.t;
                        quizletLiveInterstitialActivity3.startActivityForResult(M5.b(quizletLiveInterstitialActivity3), 1);
                        break;
                    default:
                        int i4 = QuizletLiveInterstitialActivity.q;
                        com.quizlet.data.repository.classmembership.c cVarP3 = quizletLiveInterstitialActivity.P();
                        e disposable2 = ((com.quizlet.infra.legacysyncengine.managers.d) cVarP3.a).a().i(new c(cVarP3, 0), io.reactivex.rxjava3.internal.functions.d.e);
                        Intrinsics.checkNotNullExpressionValue(disposable2, "subscribe(...)");
                        io.reactivex.rxjava3.disposables.a plusAssign2 = (io.reactivex.rxjava3.disposables.a) cVarP3.c;
                        Intrinsics.checkNotNullParameter(plusAssign2, "$this$plusAssign");
                        Intrinsics.checkNotNullParameter(disposable2, "disposable");
                        plusAssign2.b(disposable2);
                        break;
                }
            }
        });
        ImageView groupImage = ((N) K()).e;
        Intrinsics.checkNotNullExpressionValue(groupImage, "groupImage");
        int i4 = getResources().getConfiguration().orientation;
        groupImage.setVisibility((i4 != 2 && i4 == 1) ? 0 : 8);
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() {
        R();
        ((io.reactivex.rxjava3.disposables.a) P().c).dispose();
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.o;
    }
}
