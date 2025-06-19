package com.perimeterx.mobile_sdk.session;

import androidx.glance.appwidget.protobuf.Z;
import java.util.Date;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class n extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ int j;
    public int k;
    public final /* synthetic */ d l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ n(d dVar, kotlin.coroutines.h hVar, int i) {
        super(2, hVar);
        this.j = i;
        this.l = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        switch (this.j) {
            case 0:
                return new n(this.l, hVar, 0);
            case 1:
                return new n(this.l, hVar, 1);
            case 2:
                return new n(this.l, hVar, 2);
            case 3:
                return new n(this.l, hVar, 3);
            case 4:
                return new n(this.l, hVar, 4);
            case 5:
                return new n(this.l, hVar, 5);
            default:
                return new n(this.l, hVar, 6);
        }
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        kotlin.coroutines.h hVar = (kotlin.coroutines.h) obj2;
        switch (this.j) {
            case 0:
                return new n(this.l, hVar, 0).invokeSuspend(Unit.a);
            case 1:
                return new n(this.l, hVar, 1).invokeSuspend(Unit.a);
            case 2:
                return new n(this.l, hVar, 2).invokeSuspend(Unit.a);
            case 3:
                return new n(this.l, hVar, 3).invokeSuspend(Unit.a);
            case 4:
                return new n(this.l, hVar, 4).invokeSuspend(Unit.a);
            case 5:
                return new n(this.l, hVar, 5).invokeSuspend(Unit.a);
            default:
                return new n(this.l, hVar, 6).invokeSuspend(Unit.a);
        }
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        switch (this.j) {
            case 0:
                kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
                int i = this.k;
                d dVar = this.l;
                try {
                    if (i == 0) {
                        Z.e(obj);
                        com.perimeterx.mobile_sdk.api_data.j jVar = com.perimeterx.mobile_sdk.api_data.j.d;
                        this.k = 1;
                        if (dVar.b(jVar, this) == aVar) {
                            return aVar;
                        }
                    } else {
                        if (i != 1) {
                            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                        }
                        Z.e(obj);
                    }
                } catch (Exception unused) {
                }
                dVar.m();
                return Unit.a;
            case 1:
                kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
                int i2 = this.k;
                try {
                    if (i2 == 0) {
                        Z.e(obj);
                        d dVar2 = this.l;
                        com.perimeterx.mobile_sdk.api_data.j jVar2 = com.perimeterx.mobile_sdk.api_data.j.b;
                        this.k = 1;
                        if (dVar2.b(jVar2, this) == aVar2) {
                            return aVar2;
                        }
                    } else {
                        if (i2 != 1) {
                            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                        }
                        Z.e(obj);
                    }
                } catch (Exception unused2) {
                }
                return Unit.a;
            case 2:
                kotlin.coroutines.intrinsics.a aVar3 = kotlin.coroutines.intrinsics.a.a;
                int i3 = this.k;
                try {
                    if (i3 == 0) {
                        Z.e(obj);
                        d dVar3 = this.l;
                        m mVar = dVar3.b;
                        if (mVar.e == 0) {
                            this.k = 1;
                            if (dVar3.n(this) == aVar3) {
                                return aVar3;
                            }
                        } else if (mVar.g != null) {
                            if (mVar.h + 60000 < new Date().getTime()) {
                                com.perimeterx.mobile_sdk.api_data.j jVar3 = com.perimeterx.mobile_sdk.api_data.j.c;
                                this.k = 2;
                                if (dVar3.b(jVar3, this) == aVar3) {
                                    return aVar3;
                                }
                            }
                        }
                    } else if (i3 == 1) {
                        Z.e(obj);
                    } else {
                        if (i3 != 2) {
                            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                        }
                        Z.e(obj);
                    }
                } catch (Exception unused3) {
                }
                return Unit.a;
            case 3:
                kotlin.coroutines.intrinsics.a aVar4 = kotlin.coroutines.intrinsics.a.a;
                int i4 = this.k;
                if (i4 == 0) {
                    Z.e(obj);
                    com.perimeterx.mobile_sdk.api_data.j jVar4 = com.perimeterx.mobile_sdk.api_data.j.h;
                    this.k = 1;
                    if (this.l.j(jVar4, this) == aVar4) {
                        return aVar4;
                    }
                } else {
                    if (i4 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    Z.e(obj);
                }
                return Unit.a;
            case 4:
                kotlin.coroutines.intrinsics.a aVar5 = kotlin.coroutines.intrinsics.a.a;
                int i5 = this.k;
                if (i5 == 0) {
                    Z.e(obj);
                    this.k = 1;
                    if (this.l.k(this) == aVar5) {
                        return aVar5;
                    }
                } else {
                    if (i5 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    Z.e(obj);
                }
                return Unit.a;
            case 5:
                kotlin.coroutines.intrinsics.a aVar6 = kotlin.coroutines.intrinsics.a.a;
                int i6 = this.k;
                if (i6 == 0) {
                    Z.e(obj);
                    d dVar4 = this.l;
                    if (dVar4.b.g != null) {
                        this.k = 1;
                        if (dVar4.k(this) == aVar6) {
                            return aVar6;
                        }
                    }
                } else {
                    if (i6 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    Z.e(obj);
                }
                return Unit.a;
            default:
                kotlin.coroutines.intrinsics.a aVar7 = kotlin.coroutines.intrinsics.a.a;
                int i7 = this.k;
                if (i7 == 0) {
                    Z.e(obj);
                    this.k = 1;
                    if (this.l.n(this) == aVar7) {
                        return aVar7;
                    }
                } else {
                    if (i7 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    Z.e(obj);
                }
                return Unit.a;
        }
    }
}
