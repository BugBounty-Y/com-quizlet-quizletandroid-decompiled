package com.skydoves.balloon;

import androidx.glance.appwidget.protobuf.Z;
import java.util.Iterator;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.e;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.p;
import kotlin.r;
import kotlinx.coroutines.C;
import kotlinx.coroutines.C5028l;
import kotlinx.coroutines.InterfaceC5026k;

@Metadata
@e(c = "com.skydoves.balloon.Balloon$Companion$initConsumerIfNeeded$1", f = "Balloon.kt", l = {3330, 3355}, m = "invokeSuspend")
/* loaded from: classes3.dex */
public final class Balloon$Companion$initConsumerIfNeeded$1 extends i implements Function2<C, h<? super Unit>, Object> {
    private /* synthetic */ Object L$0;
    Object L$1;
    int label;

    @Metadata
    @e(c = "com.skydoves.balloon.Balloon$Companion$initConsumerIfNeeded$1$1", f = "Balloon.kt", l = {3362}, m = "invokeSuspend")
    /* renamed from: com.skydoves.balloon.Balloon$Companion$initConsumerIfNeeded$1$1, reason: invalid class name */
    public static final class AnonymousClass1 extends i implements Function2<C, h<? super Unit>, Object> {
        final /* synthetic */ Balloon $balloon;
        final /* synthetic */ DeferredBalloonGroup $group;
        final /* synthetic */ BalloonPlacement $placement;
        Object L$0;
        Object L$1;
        Object L$2;
        int label;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public AnonymousClass1(Balloon balloon, BalloonPlacement balloonPlacement, DeferredBalloonGroup deferredBalloonGroup, h<? super AnonymousClass1> hVar) {
            super(2, hVar);
            this.$balloon = balloon;
            this.$placement = balloonPlacement;
            this.$group = deferredBalloonGroup;
        }

        @Override // kotlin.coroutines.jvm.internal.a
        public final h<Unit> create(Object obj, h<?> hVar) {
            return new AnonymousClass1(this.$balloon, this.$placement, this.$group, hVar);
        }

        @Override // kotlin.coroutines.jvm.internal.a
        public final Object invokeSuspend(Object obj) {
            kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
            int i = this.label;
            if (i == 0) {
                Z.e(obj);
                Balloon balloon = this.$balloon;
                BalloonPlacement balloonPlacement = this.$placement;
                final DeferredBalloonGroup deferredBalloonGroup = this.$group;
                this.L$0 = balloon;
                this.L$1 = balloonPlacement;
                this.L$2 = deferredBalloonGroup;
                this.label = 1;
                final C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(this));
                c5028l.r();
                balloon.show(balloonPlacement);
                final OnBalloonDismissListener onBalloonDismissListener = balloon.builder.getOnBalloonDismissListener();
                balloon.setOnBalloonDismissListener(new Function0<Unit>() { // from class: com.skydoves.balloon.Balloon$Companion$initConsumerIfNeeded$1$1$1$1
                    @Override // kotlin.jvm.functions.Function0
                    public /* bridge */ /* synthetic */ Object invoke() {
                        m121invoke();
                        return Unit.a;
                    }

                    /* renamed from: invoke, reason: collision with other method in class */
                    public final void m121invoke() {
                        InterfaceC5026k interfaceC5026k = c5028l;
                        p pVar = r.b;
                        interfaceC5026k.resumeWith(Unit.a);
                        OnBalloonDismissListener onBalloonDismissListener2 = onBalloonDismissListener;
                        if (onBalloonDismissListener2 != null) {
                            onBalloonDismissListener2.onBalloonDismiss();
                        }
                        if (deferredBalloonGroup.getDismissSequentially()) {
                            return;
                        }
                        Iterator<T> it2 = deferredBalloonGroup.getBalloons().iterator();
                        while (it2.hasNext()) {
                            ((DeferredBalloon) it2.next()).getBalloon().dismiss();
                        }
                    }
                });
                Object objQ = c5028l.q();
                if (objQ == aVar) {
                    Intrinsics.checkNotNullParameter(this, "frame");
                }
                if (objQ == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            return Unit.a;
        }

        @Override // kotlin.jvm.functions.Function2
        public final Object invoke(C c, h<? super Unit> hVar) {
            return ((AnonymousClass1) create(c, hVar)).invokeSuspend(Unit.a);
        }
    }

    public Balloon$Companion$initConsumerIfNeeded$1(h<? super Balloon$Companion$initConsumerIfNeeded$1> hVar) {
        super(2, hVar);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h<Unit> create(Object obj, h<?> hVar) {
        Balloon$Companion$initConsumerIfNeeded$1 balloon$Companion$initConsumerIfNeeded$1 = new Balloon$Companion$initConsumerIfNeeded$1(hVar);
        balloon$Companion$initConsumerIfNeeded$1.L$0 = obj;
        return balloon$Companion$initConsumerIfNeeded$1;
    }

    /* JADX WARN: Code restructure failed: missing block: B:34:0x00d6, code lost:
    
        if (kotlin.collections.K.a == r0) goto L35;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x00d9, code lost:
    
        if (new kotlinx.coroutines.C4980e((kotlinx.coroutines.H[]) r5.toArray(new kotlinx.coroutines.H[0])).a(r12) == r0) goto L35;
     */
    /* JADX WARN: Removed duplicated region for block: B:14:0x004c  */
    /* JADX WARN: Removed duplicated region for block: B:17:0x0057  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x00dc  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:18:0x0065 -> B:36:0x00d9). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r13) throws java.lang.Throwable {
        /*
            r12 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r12.label
            r2 = 2
            r3 = 1
            if (r1 == 0) goto L2d
            if (r1 == r3) goto L21
            if (r1 != r2) goto L19
            java.lang.Object r1 = r12.L$1
            kotlinx.coroutines.channels.c r1 = (kotlinx.coroutines.channels.c) r1
            java.lang.Object r4 = r12.L$0
            kotlinx.coroutines.C r4 = (kotlinx.coroutines.C) r4
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto Ld9
        L19:
            java.lang.IllegalStateException r13 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r13.<init>(r0)
            throw r13
        L21:
            java.lang.Object r1 = r12.L$1
            kotlinx.coroutines.channels.c r1 = (kotlinx.coroutines.channels.c) r1
            java.lang.Object r4 = r12.L$0
            kotlinx.coroutines.C r4 = (kotlinx.coroutines.C) r4
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L4f
        L2d:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            java.lang.Object r13 = r12.L$0
            kotlinx.coroutines.C r13 = (kotlinx.coroutines.C) r13
            com.skydoves.balloon.Balloon$Companion r1 = com.skydoves.balloon.Balloon.Companion
            kotlinx.coroutines.channels.l r1 = r1.getChannel()
            kotlinx.coroutines.channels.c r1 = r1.iterator()
        L3e:
            r12.L$0 = r13
            r12.L$1 = r1
            r12.label = r3
            java.lang.Object r4 = r1.b(r12)
            if (r4 != r0) goto L4c
            goto Ld8
        L4c:
            r11 = r4
            r4 = r13
            r13 = r11
        L4f:
            java.lang.Boolean r13 = (java.lang.Boolean) r13
            boolean r13 = r13.booleanValue()
            if (r13 == 0) goto Ldc
            java.lang.Object r13 = r1.c()
            com.skydoves.balloon.DeferredBalloonGroup r13 = (com.skydoves.balloon.DeferredBalloonGroup) r13
            java.util.List r5 = r13.getBalloons()
            boolean r5 = r5.isEmpty()
            if (r5 != 0) goto Ld9
            java.util.ArrayList r5 = new java.util.ArrayList
            r5.<init>()
            java.util.List r6 = r13.getBalloons()
            java.util.Iterator r6 = r6.iterator()
        L74:
            boolean r7 = r6.hasNext()
            if (r7 == 0) goto Lb5
            java.lang.Object r7 = r6.next()
            com.skydoves.balloon.DeferredBalloon r7 = (com.skydoves.balloon.DeferredBalloon) r7
            com.skydoves.balloon.Balloon r8 = r7.component1()
            com.skydoves.balloon.BalloonPlacement r7 = r7.component2()
            android.view.View r9 = r7.getAnchor()
            boolean r9 = com.skydoves.balloon.Balloon.access$canShowBalloonWindow(r8, r9)
            if (r9 == 0) goto L74
            boolean r9 = r8.shouldShowUp()
            if (r9 != 0) goto La6
            com.skydoves.balloon.Balloon$Builder r7 = com.skydoves.balloon.Balloon.access$getBuilder$p(r8)
            kotlin.jvm.functions.Function0 r7 = r7.getRunIfReachedShowCounts()
            if (r7 == 0) goto L74
            r7.invoke()
            goto L74
        La6:
            com.skydoves.balloon.Balloon$Companion$initConsumerIfNeeded$1$1 r9 = new com.skydoves.balloon.Balloon$Companion$initConsumerIfNeeded$1$1
            r10 = 0
            r9.<init>(r8, r7, r13, r10)
            r7 = 3
            kotlinx.coroutines.I r7 = kotlinx.coroutines.E.f(r4, r10, r9, r7)
            r5.add(r7)
            goto L74
        Lb5:
            r12.L$0 = r4
            r12.L$1 = r1
            r12.label = r2
            boolean r13 = r5.isEmpty()
            if (r13 == 0) goto Lc4
            kotlin.collections.K r13 = kotlin.collections.K.a
            goto Ld6
        Lc4:
            kotlinx.coroutines.e r13 = new kotlinx.coroutines.e
            r6 = 0
            kotlinx.coroutines.H[] r6 = new kotlinx.coroutines.H[r6]
            java.lang.Object[] r5 = r5.toArray(r6)
            kotlinx.coroutines.H[] r5 = (kotlinx.coroutines.H[]) r5
            r13.<init>(r5)
            java.lang.Object r13 = r13.a(r12)
        Ld6:
            if (r13 != r0) goto Ld9
        Ld8:
            return r0
        Ld9:
            r13 = r4
            goto L3e
        Ldc:
            kotlin.Unit r13 = kotlin.Unit.a
            return r13
        */
        throw new UnsupportedOperationException("Method not decompiled: com.skydoves.balloon.Balloon$Companion$initConsumerIfNeeded$1.invokeSuspend(java.lang.Object):java.lang.Object");
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(C c, h<? super Unit> hVar) {
        return ((Balloon$Companion$initConsumerIfNeeded$1) create(c, hVar)).invokeSuspend(Unit.a);
    }
}
