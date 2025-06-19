package com.quizlet.quizletandroid.ui.studymodes.match.view;

import android.animation.Animator;
import android.animation.AnimatorInflater;
import android.content.Context;
import android.content.res.Resources;
import android.text.SpannableString;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import androidx.core.view.C1041c0;
import androidx.core.view.C1043d0;
import androidx.core.view.V;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.N6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.material.textfield.o;
import com.google.firebase.crashlytics.internal.common.i;
import com.quizlet.explanations.databinding.n;
import com.quizlet.features.match.data.C4345a;
import com.quizlet.features.match.data.C4356l;
import com.quizlet.features.match.data.C4358n;
import com.quizlet.generated.sharedconfig.b;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.managers.audio.h;
import com.quizlet.quizletandroid.util.f;
import com.quizlet.richtext.rendering.c;
import com.quizlet.richtext.ui.MatchAutoResizeTextView;
import com.quizlet.studiablemodels.StudiableImage;
import com.quizlet.studiablemodels.StudiableText;
import com.skydoves.balloon.internals.DefinitionKt;
import io.ktor.client.plugins.api.d;
import java.lang.ref.WeakReference;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class MatchCardView extends RelativeLayout {
    public static final /* synthetic */ int i = 0;
    public com.quizlet.qutils.image.loading.a a;
    public h b;
    public d c;
    public f d;
    public final Animator e;
    public C4345a f;
    public boolean g;
    public final n h;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public MatchCardView(@NotNull Context context) {
        this(context, null, 14);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public static void a(MatchCardView matchCardView, io.reactivex.rxjava3.subjects.f fVar) {
        matchCardView.setClearedState(true);
        fVar.onComplete();
    }

    private final String getLanguageCode() {
        StudiableText studiableText;
        C4345a c4345a = this.f;
        if (c4345a == null || (studiableText = c4345a.c) == null) {
            return null;
        }
        return studiableText.b;
    }

    private final View getMatchCardBorderContainer() {
        RelativeLayout matchCardBorderContainer = (RelativeLayout) this.h.d;
        Intrinsics.checkNotNullExpressionValue(matchCardBorderContainer, "matchCardBorderContainer");
        return matchCardBorderContainer;
    }

    private final View getMatchCardColor() {
        View matchCardColor = this.h.e;
        Intrinsics.checkNotNullExpressionValue(matchCardColor, "matchCardColor");
        return matchCardColor;
    }

    private final View getMatchCardImageMask() {
        View matchCardImageMask = this.h.f;
        Intrinsics.checkNotNullExpressionValue(matchCardImageMask, "matchCardImageMask");
        return matchCardImageMask;
    }

    private final ImageView getMatchImage() {
        ImageView matchImage = (ImageView) this.h.b;
        Intrinsics.checkNotNullExpressionValue(matchImage, "matchImage");
        return matchImage;
    }

    private final MatchAutoResizeTextView getMatchTextView() {
        MatchAutoResizeTextView matchTextView = (MatchAutoResizeTextView) this.h.g;
        Intrinsics.checkNotNullExpressionValue(matchTextView, "matchTextView");
        return matchTextView;
    }

    private final void setClearedState(boolean z) {
        setVisibility(z ? 4 : 0);
    }

    private final void setImage(String str) {
        if (str == null) {
            getMatchImage().setImageDrawable(null);
            getMatchImage().setVisibility(8);
            return;
        }
        getMatchImage().setVisibility(0);
        com.quizlet.qutils.image.loading.a aVar = this.a;
        if (aVar == null) {
            Intrinsics.m("imageLoader");
            throw null;
        }
        ((com.quizlet.quizletandroid.ui.common.images.loading.glide.a) aVar).a(getContext()).p(str).o(getMatchImage());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void setSelectedState(boolean z) {
        if (!z) {
            getMatchCardColor().setVisibility(4);
            getMatchCardColor().setBackgroundResource(0);
            return;
        }
        getMatchCardColor().setVisibility(0);
        Context context = getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        getMatchCardColor().setBackgroundColor(com.quizlet.themes.extensions.a.a(context, R.attr.AssemblyHighlight));
    }

    public final void c(C4345a item) {
        Intrinsics.checkNotNullParameter(item, "item");
        if (!this.g) {
            throw new IllegalStateException("MatchCardView has unfullfilled dependencies. Call setDependencies() prior to setContent()");
        }
        N6 n6 = item.a;
        if (n6 instanceof C4358n) {
            setClearedState(false);
            setSelectedState(((C4358n) n6).a);
        } else if (n6 instanceof C4356l) {
            setClearedState(true);
        }
        boolean zEquals = item.equals(this.f);
        StudiableText studiableText = item.c;
        StudiableImage studiableImage = item.d;
        if (!zEquals && !(item.a instanceof C4356l)) {
            String strA = studiableImage != null ? studiableImage.a() : null;
            setImage(strA);
            i();
            h(studiableText, strA != null);
        }
        this.f = new C4345a(item.b, studiableText, studiableImage, item.e);
    }

    public final io.reactivex.rxjava3.subjects.f d() {
        Context context = getContext();
        com.quizlet.quizletandroid.util.d.a(context, context.getString(R.string.match_correct_answer_description));
        io.reactivex.rxjava3.subjects.f fVar = new io.reactivex.rxjava3.subjects.f();
        Intrinsics.checkNotNullExpressionValue(fVar, "create(...)");
        Context context2 = getContext();
        Intrinsics.checkNotNullExpressionValue(context2, "getContext(...)");
        getMatchCardColor().setBackgroundColor(com.quizlet.themes.extensions.a.a(context2, R.attr.colorControlSuccess));
        getMatchCardColor().setVisibility(0);
        C1043d0 c1043d0A = V.a(this);
        c1043d0A.a(DefinitionKt.NO_Float_VALUE);
        WeakReference weakReference = c1043d0A.a;
        View view = (View) weakReference.get();
        if (view != null) {
            view.animate().scaleX(DefinitionKt.NO_Float_VALUE);
        }
        View view2 = (View) weakReference.get();
        if (view2 != null) {
            view2.animate().scaleY(DefinitionKt.NO_Float_VALUE);
        }
        c1043d0A.c(getResources().getInteger(R.integer.animation_duration_standard));
        View view3 = (View) weakReference.get();
        if (view3 != null) {
            view3.animate().withLayer();
        }
        i iVar = new i(28, this, fVar);
        View view4 = (View) weakReference.get();
        if (view4 != null) {
            view4.animate().withEndAction(iVar);
        }
        return fVar;
    }

    public final io.reactivex.rxjava3.subjects.f e() {
        Context context = getContext();
        com.quizlet.quizletandroid.util.d.a(context, context.getString(R.string.match_incorrect_answer_description));
        io.reactivex.rxjava3.subjects.f fVar = new io.reactivex.rxjava3.subjects.f();
        Intrinsics.checkNotNullExpressionValue(fVar, "create(...)");
        Context context2 = getContext();
        Intrinsics.checkNotNullExpressionValue(context2, "getContext(...)");
        getMatchCardColor().setBackgroundColor(com.quizlet.themes.extensions.a.a(context2, R.attr.colorControlError));
        getMatchCardColor().setVisibility(0);
        Animator animator = this.e;
        if (animator == null) {
            Intrinsics.m("incorrectAnim");
            throw null;
        }
        animator.removeAllListeners();
        Animator animator2 = this.e;
        if (animator2 == null) {
            Intrinsics.m("incorrectAnim");
            throw null;
        }
        animator2.addListener(new C1041c0(4, this, fVar));
        Animator animator3 = this.e;
        if (animator3 != null) {
            animator3.start();
            return fVar;
        }
        Intrinsics.m("incorrectAnim");
        throw null;
    }

    public final void f() {
        setClearedState(false);
        this.f = null;
        h(null, false);
        setImage(null);
        setSelectedState(false);
    }

    public final void g(com.quizlet.qutils.image.loading.a imageLoader, h audioManager, d audioPlayFailureManager, c richTextRenderer, f languageUtil) {
        Intrinsics.checkNotNullParameter(imageLoader, "imageLoader");
        Intrinsics.checkNotNullParameter(audioManager, "audioManager");
        Intrinsics.checkNotNullParameter(audioPlayFailureManager, "audioPlayFailureManager");
        Intrinsics.checkNotNullParameter(richTextRenderer, "richTextRenderer");
        Intrinsics.checkNotNullParameter(languageUtil, "languageUtil");
        this.a = imageLoader;
        this.b = audioManager;
        this.c = audioPlayFailureManager;
        this.d = languageUtil;
        getMatchTextView().setRichTextRenderer(richTextRenderer);
        this.g = true;
    }

    public final void h(StudiableText studiableText, boolean z) {
        SpannableString spannableString;
        String str;
        f fVar = this.d;
        com.quizlet.richtext.model.a aVar = null;
        if (fVar == null) {
            Intrinsics.m("languageUtil");
            throw null;
        }
        Context context = getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        String str2 = studiableText != null ? studiableText.a : null;
        String str3 = studiableText != null ? studiableText.b : null;
        Intrinsics.checkNotNullParameter(context, "context");
        if (str2 == null || str2.length() == 0) {
            spannableString = new SpannableString("");
        } else if (str2.length() > 80) {
            CharSequence charSequenceSubSequence = str2.subSequence(0, 80);
            spannableString = new SpannableString(((Object) charSequenceSubSequence) + context.getString(R.string.elipsis));
        } else {
            spannableString = (z && str2.length() == 0) ? new SpannableString(str2) : fVar.c(context, str2, str3);
        }
        if (spannableString.length() == 0) {
            getMatchTextView().setText((CharSequence) null);
            getMatchTextView().setVisibility(8);
            getMatchCardImageMask().setVisibility(8);
        } else {
            getMatchTextView().setVisibility(0);
            getMatchCardImageMask().setVisibility(0);
            if (studiableText != null && (str = studiableText.c) != null) {
                aVar = new com.quizlet.richtext.model.a(str);
            }
            getMatchTextView().h(aVar, spannableString, false);
        }
    }

    /* JADX WARN: Type inference failed for: r3v0, types: [java.lang.Object, java.util.Map] */
    public final void i() {
        float f;
        int i2 = getResources().getDisplayMetrics().densityDpi;
        if (i2 < 270) {
            f = 15.0f;
        } else if (i2 < 350) {
            f = (13 * ((i2 - SubsamplingScaleImageView.ORIENTATION_270) / 80.0f)) + 15;
        } else {
            f = 28.0f;
        }
        MatchAutoResizeTextView matchTextView = getMatchTextView();
        String languageCode = getLanguageCode();
        matchTextView.getClass();
        com.quizlet.generated.sharedconfig.a aVar = (com.quizlet.generated.sharedconfig.a) b.c.get(languageCode);
        if (aVar != null) {
            float f2 = aVar.a;
            if (f2 > DefinitionKt.NO_Float_VALUE) {
                f *= f2;
            }
        }
        matchTextView.b.e = f;
        matchTextView.requestLayout();
        matchTextView.invalidate();
        getMatchTextView().setMaxTextSize(150.0f);
        getMatchTextView().j();
        getMatchTextView().setTextSize(getMatchTextView().getMinTextSize());
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public MatchCardView(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 12);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public MatchCardView(Context context, AttributeSet attributeSet, int i2) throws Resources.NotFoundException {
        attributeSet = (i2 & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, 0, 0);
        LayoutInflater.from(context).inflate(R.layout.match_card_view, this);
        int i3 = R.id.matchCardBorderContainer;
        RelativeLayout relativeLayout = (RelativeLayout) AbstractC3375o2.c(R.id.matchCardBorderContainer, this);
        if (relativeLayout != null) {
            i3 = R.id.matchCardColor;
            View viewC = AbstractC3375o2.c(R.id.matchCardColor, this);
            if (viewC != null) {
                i3 = R.id.matchCardImageMask;
                View viewC2 = AbstractC3375o2.c(R.id.matchCardImageMask, this);
                if (viewC2 != null) {
                    i3 = R.id.matchImage;
                    ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.matchImage, this);
                    if (imageView != null) {
                        i3 = R.id.matchTextView;
                        MatchAutoResizeTextView matchAutoResizeTextView = (MatchAutoResizeTextView) AbstractC3375o2.c(R.id.matchTextView, this);
                        if (matchAutoResizeTextView != null) {
                            n nVar = new n(this, relativeLayout, viewC, viewC2, imageView, matchAutoResizeTextView);
                            Intrinsics.checkNotNullExpressionValue(nVar, "inflate(...)");
                            this.h = nVar;
                            i();
                            Animator animatorLoadAnimator = AnimatorInflater.loadAnimator(getContext(), R.animator.match_incorrect_card);
                            this.e = animatorLoadAnimator;
                            if (animatorLoadAnimator != null) {
                                animatorLoadAnimator.setTarget(this);
                                getMatchCardBorderContainer().setBackground(com.quizlet.themes.extensions.a.c(context, R.drawable.bg_match_cell, R.attr.colorCardBorder));
                                setAccessibilityDelegate(new o(this, 1));
                                return;
                            }
                            Intrinsics.m("incorrectAnim");
                            throw null;
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(getResources().getResourceName(i3)));
    }
}
