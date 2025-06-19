package com.braze.ui.actions.brazeactions.steps;

import com.braze.Braze;
import com.braze.BrazeUser;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public abstract class BaseBrazeActionStep implements IBrazeActionStep {

    @NotNull
    public static final Companion Companion = new Companion(null);

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void runOnUser$android_sdk_ui_release(@NotNull Braze braze, @NotNull Function1<? super BrazeUser, Unit> block) {
            Intrinsics.checkNotNullParameter(braze, "<this>");
            Intrinsics.checkNotNullParameter(block, "block");
            braze.getCurrentUser(new BaseBrazeActionStep$Companion$runOnUser$1(block));
        }

        private Companion() {
        }
    }

    public /* synthetic */ BaseBrazeActionStep(DefaultConstructorMarker defaultConstructorMarker) {
        this();
    }

    private BaseBrazeActionStep() {
    }
}
