package com.sdk.growthbook.features;

import androidx.glance.appwidget.protobuf.Z;
import com.appsflyer.attribution.RequestError;
import com.comscore.streaming.AdvertisementType;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.e;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.InterfaceC5002j;
import org.jetbrains.annotations.NotNull;

@Metadata
@e(c = "com.sdk.growthbook.features.FeaturesDataSource$autoRefresh$$inlined$transform$1", f = "FeaturesDataSource.kt", l = {RequestError.NETWORK_FAILURE}, m = "invokeSuspend")
/* loaded from: classes3.dex */
public final class FeaturesDataSource$autoRefresh$$inlined$transform$1 extends i implements Function2<InterfaceC5002j, h<? super Unit>, Object> {
    final /* synthetic */ Function1 $failure$inlined;
    final /* synthetic */ Function1 $success$inlined;
    final /* synthetic */ InterfaceC4992i $this_transform;
    private /* synthetic */ Object L$0;
    int label;
    final /* synthetic */ FeaturesDataSource this$0;

    @Metadata
    /* renamed from: com.sdk.growthbook.features.FeaturesDataSource$autoRefresh$$inlined$transform$1$1, reason: invalid class name */
    public static final class AnonymousClass1<T> implements InterfaceC5002j {
        final /* synthetic */ InterfaceC5002j $$this$flow;
        final /* synthetic */ Function1 $failure$inlined;
        final /* synthetic */ Function1 $success$inlined;
        final /* synthetic */ FeaturesDataSource this$0;

        @Metadata
        @e(c = "com.sdk.growthbook.features.FeaturesDataSource$autoRefresh$$inlined$transform$1$1", f = "FeaturesDataSource.kt", l = {230, AdvertisementType.BRANDED_ON_DEMAND_POST_ROLL}, m = "emit")
        /* renamed from: com.sdk.growthbook.features.FeaturesDataSource$autoRefresh$$inlined$transform$1$1$1, reason: invalid class name and collision with other inner class name */
        public static final class C00241 extends kotlin.coroutines.jvm.internal.c {
            Object L$0;
            Object L$1;
            int label;
            /* synthetic */ Object result;

            public C00241(h hVar) {
                super(hVar);
            }

            @Override // kotlin.coroutines.jvm.internal.a
            public final Object invokeSuspend(@NotNull Object obj) {
                this.result = obj;
                this.label |= Integer.MIN_VALUE;
                return AnonymousClass1.this.emit(null, this);
            }
        }

        public AnonymousClass1(InterfaceC5002j interfaceC5002j, FeaturesDataSource featuresDataSource, Function1 function1, Function1 function12) {
            this.this$0 = featuresDataSource;
            this.$success$inlined = function1;
            this.$failure$inlined = function12;
            this.$$this$flow = interfaceC5002j;
        }

        /* JADX WARN: Multi-variable type inference failed */
        /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
        @Override // kotlinx.coroutines.flow.InterfaceC5002j
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public final java.lang.Object emit(T r6, @org.jetbrains.annotations.NotNull kotlin.coroutines.h<? super kotlin.Unit> r7) {
            /*
                r5 = this;
                boolean r0 = r7 instanceof com.sdk.growthbook.features.FeaturesDataSource$autoRefresh$$inlined$transform$1.AnonymousClass1.C00241
                if (r0 == 0) goto L13
                r0 = r7
                com.sdk.growthbook.features.FeaturesDataSource$autoRefresh$$inlined$transform$1$1$1 r0 = (com.sdk.growthbook.features.FeaturesDataSource$autoRefresh$$inlined$transform$1.AnonymousClass1.C00241) r0
                int r1 = r0.label
                r2 = -2147483648(0xffffffff80000000, float:-0.0)
                r3 = r1 & r2
                if (r3 == 0) goto L13
                int r1 = r1 - r2
                r0.label = r1
                goto L18
            L13:
                com.sdk.growthbook.features.FeaturesDataSource$autoRefresh$$inlined$transform$1$1$1 r0 = new com.sdk.growthbook.features.FeaturesDataSource$autoRefresh$$inlined$transform$1$1$1
                r0.<init>(r7)
            L18:
                java.lang.Object r7 = r0.result
                kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
                int r2 = r0.label
                r3 = 2
                r4 = 1
                if (r2 == 0) goto L46
                if (r2 == r4) goto L3a
                if (r2 != r3) goto L32
                java.lang.Object r6 = r0.L$1
                com.sdk.growthbook.utils.Resource r6 = (com.sdk.growthbook.utils.Resource) r6
                java.lang.Object r0 = r0.L$0
                com.sdk.growthbook.features.FeaturesDataSource$autoRefresh$$inlined$transform$1$1 r0 = (com.sdk.growthbook.features.FeaturesDataSource$autoRefresh$$inlined$transform$1.AnonymousClass1) r0
                androidx.glance.appwidget.protobuf.Z.e(r7)
                goto L9e
            L32:
                java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
                java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
                r6.<init>(r7)
                throw r6
            L3a:
                java.lang.Object r6 = r0.L$1
                com.sdk.growthbook.features.FeaturesDataModel r6 = (com.sdk.growthbook.features.FeaturesDataModel) r6
                java.lang.Object r0 = r0.L$0
                com.sdk.growthbook.features.FeaturesDataSource$autoRefresh$$inlined$transform$1$1 r0 = (com.sdk.growthbook.features.FeaturesDataSource$autoRefresh$$inlined$transform$1.AnonymousClass1) r0
                androidx.glance.appwidget.protobuf.Z.e(r7)
                goto L86
            L46:
                androidx.glance.appwidget.protobuf.Z.e(r7)
                kotlinx.coroutines.flow.j r7 = r5.$$this$flow
                com.sdk.growthbook.utils.Resource r6 = (com.sdk.growthbook.utils.Resource) r6
                boolean r2 = r6 instanceof com.sdk.growthbook.utils.Resource.Success
                if (r2 == 0) goto L8c
                com.sdk.growthbook.features.FeaturesDataSource r2 = r5.this$0
                kotlinx.serialization.json.c r2 = com.sdk.growthbook.features.FeaturesDataSource.access$getJsonParser(r2)
                com.sdk.growthbook.serializable_model.SerializableFeaturesDataModel$Companion r3 = com.sdk.growthbook.serializable_model.SerializableFeaturesDataModel.Companion
                kotlinx.serialization.KSerializer r3 = r3.serializer()
                com.sdk.growthbook.utils.Resource$Success r6 = (com.sdk.growthbook.utils.Resource.Success) r6
                java.lang.Object r6 = r6.getData()
                java.lang.String r6 = (java.lang.String) r6
                java.lang.Object r6 = r2.b(r6, r3)
                com.sdk.growthbook.serializable_model.SerializableFeaturesDataModel r6 = (com.sdk.growthbook.serializable_model.SerializableFeaturesDataModel) r6
                com.sdk.growthbook.features.FeaturesDataModel r6 = com.sdk.growthbook.serializable_model.SerializableFeaturesDataModelKt.gbDeserialize(r6)
                java.util.Map r2 = r6.getFeatures()
                com.sdk.growthbook.utils.Resource$Success r3 = new com.sdk.growthbook.utils.Resource$Success
                r3.<init>(r2)
                r0.L$0 = r5
                r0.L$1 = r6
                r0.label = r4
                java.lang.Object r7 = r7.emit(r3, r0)
                if (r7 != r1) goto L85
                goto L9c
            L85:
                r0 = r5
            L86:
                kotlin.jvm.functions.Function1 r7 = r0.$success$inlined
                r7.invoke(r6)
                goto La9
            L8c:
                boolean r2 = r6 instanceof com.sdk.growthbook.utils.Resource.Error
                if (r2 == 0) goto La9
                r0.L$0 = r5
                r0.L$1 = r6
                r0.label = r3
                java.lang.Object r7 = r7.emit(r6, r0)
                if (r7 != r1) goto L9d
            L9c:
                return r1
            L9d:
                r0 = r5
            L9e:
                com.sdk.growthbook.utils.Resource$Error r6 = (com.sdk.growthbook.utils.Resource.Error) r6
                java.lang.Exception r6 = r6.getException()
                kotlin.jvm.functions.Function1 r7 = r0.$failure$inlined
                r7.invoke(r6)
            La9:
                kotlin.Unit r6 = kotlin.Unit.a
                return r6
            */
            throw new UnsupportedOperationException("Method not decompiled: com.sdk.growthbook.features.FeaturesDataSource$autoRefresh$$inlined$transform$1.AnonymousClass1.emit(java.lang.Object, kotlin.coroutines.h):java.lang.Object");
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public FeaturesDataSource$autoRefresh$$inlined$transform$1(InterfaceC4992i interfaceC4992i, h hVar, FeaturesDataSource featuresDataSource, Function1 function1, Function1 function12) {
        super(2, hVar);
        this.$this_transform = interfaceC4992i;
        this.this$0 = featuresDataSource;
        this.$success$inlined = function1;
        this.$failure$inlined = function12;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    @NotNull
    public final h<Unit> create(Object obj, @NotNull h<?> hVar) {
        FeaturesDataSource$autoRefresh$$inlined$transform$1 featuresDataSource$autoRefresh$$inlined$transform$1 = new FeaturesDataSource$autoRefresh$$inlined$transform$1(this.$this_transform, hVar, this.this$0, this.$success$inlined, this.$failure$inlined);
        featuresDataSource$autoRefresh$$inlined$transform$1.L$0 = obj;
        return featuresDataSource$autoRefresh$$inlined$transform$1;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(@NotNull Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.label;
        if (i == 0) {
            Z.e(obj);
            InterfaceC5002j interfaceC5002j = (InterfaceC5002j) this.L$0;
            InterfaceC4992i interfaceC4992i = this.$this_transform;
            AnonymousClass1 anonymousClass1 = new AnonymousClass1(interfaceC5002j, this.this$0, this.$success$inlined, this.$failure$inlined);
            this.label = 1;
            if (interfaceC4992i.b(anonymousClass1, this) == aVar) {
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
    public final Object invoke(@NotNull InterfaceC5002j interfaceC5002j, h<? super Unit> hVar) {
        return ((FeaturesDataSource$autoRefresh$$inlined$transform$1) create(interfaceC5002j, hVar)).invokeSuspend(Unit.a);
    }
}
