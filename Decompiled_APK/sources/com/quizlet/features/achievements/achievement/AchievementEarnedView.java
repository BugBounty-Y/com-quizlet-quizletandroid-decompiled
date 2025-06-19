package com.quizlet.features.achievements.achievement;

import android.content.Context;
import android.content.res.Resources;
import android.util.AttributeSet;
import android.view.GestureDetector;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;
import androidx.compose.ui.platform.ComposeView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.firebase.crashlytics.internal.metadata.q;
import com.quizlet.eventlogger.features.achievements.AchievementsToastInteractionEventLog;
import com.quizlet.eventlogger.features.achievements.AchievementsToastInteractionLogger;
import com.quizlet.generated.enums.EnumC4485h;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class AchievementEarnedView extends com.google.android.material.card.b {
    public static final /* synthetic */ int s = 0;
    public d o;
    public EnumC4485h p;
    public final com.google.firebase.platforminfo.c q;
    public final com.quizlet.assembly.databinding.d r;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AchievementEarnedView(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public static /* synthetic */ void getListener$annotations() {
    }

    @Override // android.view.ViewGroup, android.view.View
    public final boolean dispatchTouchEvent(MotionEvent event) {
        Intrinsics.checkNotNullParameter(event, "event");
        super.dispatchTouchEvent(event);
        return ((GestureDetector) this.q.a).onTouchEvent(event);
    }

    public final void g(a data) {
        Intrinsics.checkNotNullParameter(data, "data");
        EnumC4485h notificationType = data.a;
        this.p = notificationType;
        Context context = getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        setStrokeColor(com.quizlet.themes.extensions.a.a(context, data.c.b));
        com.quizlet.assembly.databinding.d dVar = this.r;
        dVar.b.setContent(new androidx.compose.runtime.internal.d(true, 1546842772, new com.quizlet.assembly.compose.cards.c(data, 8)));
        AchievementEarnedView achievementEarnedView = dVar.a;
        Intrinsics.checkNotNullExpressionValue(achievementEarnedView, "getRoot(...)");
        achievementEarnedView.setVisibility(0);
        achievementEarnedView.postDelayed(new q(this, 9), 5000L);
        d dVar2 = this.o;
        if (dVar2 != null) {
            com.quizlet.features.achievements.notification.f fVar = (com.quizlet.features.achievements.notification.f) dVar2;
            Intrinsics.checkNotNullParameter(notificationType, "notificationType");
            fVar.e.getClass();
            fVar.h = com.quizlet.time.b.a();
            String notificationType2 = notificationType.a();
            AchievementsToastInteractionLogger achievementsToastInteractionLogger = fVar.d;
            achievementsToastInteractionLogger.getClass();
            Intrinsics.checkNotNullParameter(notificationType2, "notificationType");
            AchievementsToastInteractionEventLog.Companion companion = AchievementsToastInteractionEventLog.b;
            androidx.navigation.internal.h hVar = new androidx.navigation.internal.h(notificationType2, 16);
            companion.getClass();
            achievementsToastInteractionLogger.a(AchievementsToastInteractionEventLog.Companion.a("achievements_toast_shown", hVar));
        }
    }

    @NotNull
    public final com.quizlet.assembly.databinding.d getBinding() {
        return this.r;
    }

    public final d getListener() {
        return this.o;
    }

    public final void h(e reason) {
        Intrinsics.checkNotNullParameter(reason, "reason");
        int iOrdinal = reason.ordinal();
        if (iOrdinal == 0) {
            i();
            return;
        }
        if (iOrdinal != 1) {
            if (iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
            i();
            d dVar = this.o;
            if (dVar != null) {
                EnumC4485h enumC4485h = this.p;
                if (enumC4485h != null) {
                    ((com.quizlet.features.achievements.notification.f) dVar).B(enumC4485h);
                    return;
                } else {
                    Intrinsics.m("notificationType");
                    throw null;
                }
            }
            return;
        }
        AchievementEarnedView achievementEarnedView = this.r.a;
        Intrinsics.checkNotNullExpressionValue(achievementEarnedView, "getRoot(...)");
        achievementEarnedView.setVisibility(8);
        d dVar2 = this.o;
        if (dVar2 != null) {
            EnumC4485h enumC4485h2 = this.p;
            if (enumC4485h2 != null) {
                ((com.quizlet.features.achievements.notification.f) dVar2).B(enumC4485h2);
            } else {
                Intrinsics.m("notificationType");
                throw null;
            }
        }
    }

    public final void i() throws Resources.NotFoundException {
        Animation animationLoadAnimation = AnimationUtils.loadAnimation(getContext(), R.anim.slide_down);
        Intrinsics.checkNotNullExpressionValue(animationLoadAnimation, "loadAnimation(...)");
        animationLoadAnimation.setAnimationListener(new f(this, 0));
        this.r.a.startAnimation(animationLoadAnimation);
    }

    @Override // android.view.View
    public final boolean onTouchEvent(MotionEvent motionEvent) {
        if (motionEvent != null) {
            return ((GestureDetector) this.q.a).onTouchEvent(motionEvent);
        }
        return false;
    }

    public final void setListener(d dVar) {
        this.o = dVar;
    }

    public final void setOnAchievementEventListener(d dVar) {
        this.o = dVar;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AchievementEarnedView(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public AchievementEarnedView(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, 0);
        b bVar = new b(new c(this, 0), new c(this, 1));
        com.google.firebase.platforminfo.c cVar = new com.google.firebase.platforminfo.c();
        cVar.a = new GestureDetector(context, bVar, null);
        this.q = cVar;
        LayoutInflater.from(context).inflate(R.layout.view_compose_wrapper, this);
        ComposeView composeView = (ComposeView) AbstractC3375o2.c(R.id.composeView, this);
        if (composeView != null) {
            com.quizlet.assembly.databinding.d dVar = new com.quizlet.assembly.databinding.d(this, composeView);
            Intrinsics.checkNotNullExpressionValue(dVar, "inflate(...)");
            this.r = dVar;
            setRadius(getResources().getDimensionPixelOffset(R.dimen.ref_radius_small));
            setStrokeWidth(getResources().getDimensionPixelOffset(R.dimen.achievement_notification_stroke_size));
            setElevation(getResources().getDimensionPixelOffset(R.dimen.achievement_notification_elevation));
            return;
        }
        throw new NullPointerException("Missing required view with ID: ".concat(getResources().getResourceName(R.id.composeView)));
    }
}
