package com.braze.ui.inappmessage.jsinterface;

import android.content.Context;
import android.webkit.JavascriptInterface;
import androidx.glance.appwidget.protobuf.Z;
import com.braze.coroutine.BrazeCoroutineScope;
import com.braze.models.inappmessage.IInAppMessageHtml;
import com.braze.support.BrazeLogger;
import com.braze.support.PermissionUtils;
import com.braze.ui.JavascriptInterfaceBase;
import com.braze.ui.inappmessage.BrazeInAppMessageManager;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.e;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class InAppMessageJavascriptInterface extends JavascriptInterfaceBase {

    @NotNull
    public static final Companion Companion = new Companion(null);

    @NotNull
    private final IInAppMessageHtml inAppMessage;

    @NotNull
    private final InAppMessageUserJavascriptInterface user;
    private boolean wasCloseMessageCalled;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    @Metadata
    @e(c = "com.braze.ui.inappmessage.jsinterface.InAppMessageJavascriptInterface$requestPushPermission$1", f = "InAppMessageJavascriptInterface.kt", l = {52}, m = "invokeSuspend")
    /* renamed from: com.braze.ui.inappmessage.jsinterface.InAppMessageJavascriptInterface$requestPushPermission$1, reason: invalid class name */
    public static final class AnonymousClass1 extends i implements Function1<h<? super Unit>, Object> {
        int label;

        @Metadata
        @e(c = "com.braze.ui.inappmessage.jsinterface.InAppMessageJavascriptInterface$requestPushPermission$1$1", f = "InAppMessageJavascriptInterface.kt", l = {55}, m = "invokeSuspend")
        /* renamed from: com.braze.ui.inappmessage.jsinterface.InAppMessageJavascriptInterface$requestPushPermission$1$1, reason: invalid class name and collision with other inner class name */
        public static final class C00011 extends i implements Function2<C, h<? super Unit>, Object> {
            private /* synthetic */ Object L$0;
            int label;

            public C00011(h<? super C00011> hVar) {
                super(2, hVar);
            }

            /* JADX INFO: Access modifiers changed from: private */
            public static final String invokeSuspend$lambda$0() {
                return "Waiting for IAM to be fully closed before requesting push prompt";
            }

            @Override // kotlin.coroutines.jvm.internal.a
            public final h<Unit> create(Object obj, h<?> hVar) {
                C00011 c00011 = new C00011(hVar);
                c00011.L$0 = obj;
                return c00011;
            }

            @Override // kotlin.coroutines.jvm.internal.a
            public final Object invokeSuspend(Object obj) {
                kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
                int i = this.label;
                if (i == 0) {
                    Z.e(obj);
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, this.L$0, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new a(1), 6, (Object) null);
                } else {
                    if (i != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    Z.e(obj);
                }
                while (BrazeInAppMessageManager.Companion.getInstance().isCurrentlyDisplayingInAppMessage()) {
                    this.label = 1;
                    if (E.n(25L, this) == aVar) {
                        return aVar;
                    }
                }
                return Unit.a;
            }

            @Override // kotlin.jvm.functions.Function2
            public final Object invoke(C c, h<? super Unit> hVar) {
                return ((C00011) create(c, hVar)).invokeSuspend(Unit.a);
            }
        }

        public AnonymousClass1(h<? super AnonymousClass1> hVar) {
            super(1, hVar);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String invokeSuspend$lambda$0() {
            return "Requesting push prompt from Braze bridge html interface";
        }

        @Override // kotlin.coroutines.jvm.internal.a
        public final h<Unit> create(h<?> hVar) {
            return InAppMessageJavascriptInterface.this.new AnonymousClass1(hVar);
        }

        @Override // kotlin.coroutines.jvm.internal.a
        public final Object invokeSuspend(Object obj) {
            kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
            int i = this.label;
            if (i == 0) {
                Z.e(obj);
                if (InAppMessageJavascriptInterface.this.getWasCloseMessageCalled()) {
                    C00011 c00011 = new C00011(null);
                    this.label = 1;
                    if (E.K(2500L, c00011, this) == aVar) {
                        return aVar;
                    }
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) InAppMessageJavascriptInterface.this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new a(0), 6, (Object) null);
            PermissionUtils.requestPushPermissionPrompt(BrazeInAppMessageManager.Companion.getInstance().getActivity());
            return Unit.a;
        }

        @Override // kotlin.jvm.functions.Function1
        public final Object invoke(h<? super Unit> hVar) {
            return ((AnonymousClass1) create(hVar)).invokeSuspend(Unit.a);
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public InAppMessageJavascriptInterface(@NotNull Context context, @NotNull IInAppMessageHtml inAppMessage) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(inAppMessage, "inAppMessage");
        this.inAppMessage = inAppMessage;
        this.user = new InAppMessageUserJavascriptInterface(context);
    }

    @JavascriptInterface
    public final void beforeMessageClosed() {
        this.wasCloseMessageCalled = true;
    }

    @JavascriptInterface
    @NotNull
    public final InAppMessageUserJavascriptInterface getUser() {
        return this.user;
    }

    public final boolean getWasCloseMessageCalled() {
        return this.wasCloseMessageCalled;
    }

    @Override // com.braze.ui.JavascriptInterfaceBase
    @JavascriptInterface
    public void logButtonClick(String str) {
        if (str != null) {
            this.inAppMessage.logButtonClick(str);
        }
    }

    @Override // com.braze.ui.JavascriptInterfaceBase
    @JavascriptInterface
    public void logClick() {
        this.inAppMessage.logClick();
    }

    @JavascriptInterface
    public final void requestPushPermission() {
        BrazeInAppMessageManager.Companion.getInstance().setShouldNextUnregisterBeSkipped(true);
        BrazeCoroutineScope.launchDelayed$default(BrazeCoroutineScope.INSTANCE, 75L, null, new AnonymousClass1(null), 2, null);
    }
}
