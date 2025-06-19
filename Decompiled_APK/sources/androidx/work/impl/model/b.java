package androidx.work.impl.model;

import android.net.NetworkRequest;
import android.os.Build;
import androidx.compose.runtime.AbstractC0772a;
import androidx.work.A;
import androidx.work.C1424e;
import androidx.work.C1425f;
import androidx.work.C1437k;
import androidx.work.EnumC1420a;
import androidx.work.J;
import androidx.work.impl.WorkDatabase;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3390s2;
import com.google.android.gms.internal.mlkit_vision_camera.B2;
import com.google.android.gms.internal.mlkit_vision_camera.F2;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.Set;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b extends AbstractC0772a {
    public final /* synthetic */ int d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ b(WorkDatabase workDatabase, int i) {
        super(workDatabase);
        this.d = i;
    }

    @Override // androidx.compose.runtime.AbstractC0772a
    public final String j() {
        switch (this.d) {
            case 0:
                return "INSERT OR IGNORE INTO `Dependency` (`work_spec_id`,`prerequisite_id`) VALUES (?,?)";
            case 1:
                return "INSERT OR REPLACE INTO `Preference` (`key`,`long_value`) VALUES (?,?)";
            case 2:
                return "INSERT OR REPLACE INTO `SystemIdInfo` (`work_spec_id`,`generation`,`system_id`) VALUES (?,?,?)";
            case 3:
                return "INSERT OR IGNORE INTO `WorkName` (`name`,`work_spec_id`) VALUES (?,?)";
            case 4:
                return "INSERT OR REPLACE INTO `WorkProgress` (`work_spec_id`,`progress`) VALUES (?,?)";
            case 5:
                return "INSERT OR IGNORE INTO `WorkSpec` (`id`,`state`,`worker_class_name`,`input_merger_class_name`,`input`,`output`,`initial_delay`,`interval_duration`,`flex_duration`,`run_attempt_count`,`backoff_policy`,`backoff_delay_duration`,`last_enqueue_time`,`minimum_retention_duration`,`schedule_requested_at`,`run_in_foreground`,`out_of_quota_policy`,`period_count`,`generation`,`next_schedule_time_override`,`next_schedule_time_override_generation`,`stop_reason`,`trace_tag`,`required_network_type`,`required_network_request`,`requires_charging`,`requires_device_idle`,`requires_battery_not_low`,`requires_storage_not_low`,`trigger_content_update_delay`,`trigger_max_content_delay`,`content_uri_triggers`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
            default:
                return "INSERT OR IGNORE INTO `WorkTag` (`tag`,`work_spec_id`) VALUES (?,?)";
        }
    }

    /* JADX WARN: Finally extract failed */
    public final void o(androidx.sqlite.db.framework.i iVar, Object obj) throws IOException {
        int i;
        int i2;
        byte[] byteArray;
        byte[] byteArray2;
        int i3 = 5;
        switch (this.d) {
            case 0:
                a aVar = (a) obj;
                iVar.g(1, aVar.a);
                iVar.g(2, aVar.b);
                return;
            case 1:
                d dVar = (d) obj;
                iVar.g(1, dVar.a);
                iVar.z(2, dVar.b.longValue());
                return;
            case 2:
                iVar.g(1, ((g) obj).a);
                iVar.z(2, r15.b);
                iVar.z(3, r15.c);
                return;
            case 3:
                k kVar = (k) obj;
                iVar.g(1, kVar.a);
                iVar.g(2, kVar.b);
                return;
            case 4:
                m mVar = (m) obj;
                iVar.g(1, mVar.a);
                C1437k c1437k = C1437k.b;
                iVar.E(2, AbstractC3390s2.d(mVar.b));
                return;
            case 5:
                q qVar = (q) obj;
                iVar.g(1, qVar.a);
                iVar.z(2, B2.g(qVar.b));
                iVar.g(3, qVar.c);
                iVar.g(4, qVar.d);
                C1437k c1437k2 = qVar.e;
                C1437k c1437k3 = C1437k.b;
                iVar.E(5, AbstractC3390s2.d(c1437k2));
                iVar.E(6, AbstractC3390s2.d(qVar.f));
                iVar.z(7, qVar.g);
                iVar.z(8, qVar.h);
                iVar.z(9, qVar.i);
                iVar.z(10, qVar.k);
                EnumC1420a backoffPolicy = qVar.l;
                Intrinsics.checkNotNullParameter(backoffPolicy, "backoffPolicy");
                int iOrdinal = backoffPolicy.ordinal();
                if (iOrdinal == 0) {
                    i = 0;
                } else {
                    if (iOrdinal != 1) {
                        throw new NoWhenBranchMatchedException();
                    }
                    i = 1;
                }
                iVar.z(11, i);
                iVar.z(12, qVar.m);
                iVar.z(13, qVar.n);
                iVar.z(14, qVar.o);
                iVar.z(15, qVar.p);
                iVar.z(16, qVar.q ? 1L : 0L);
                J policy = qVar.r;
                Intrinsics.checkNotNullParameter(policy, "policy");
                int iOrdinal2 = policy.ordinal();
                if (iOrdinal2 == 0) {
                    i2 = 0;
                } else {
                    if (iOrdinal2 != 1) {
                        throw new NoWhenBranchMatchedException();
                    }
                    i2 = 1;
                }
                iVar.z(17, i2);
                iVar.z(18, qVar.s);
                iVar.z(19, qVar.t);
                iVar.z(20, qVar.u);
                iVar.z(21, qVar.v);
                iVar.z(22, qVar.w);
                String str = qVar.x;
                if (str == null) {
                    iVar.R(23);
                } else {
                    iVar.g(23, str);
                }
                C1425f c1425f = qVar.j;
                A networkType = c1425f.a;
                Intrinsics.checkNotNullParameter(networkType, "networkType");
                int iOrdinal3 = networkType.ordinal();
                if (iOrdinal3 == 0) {
                    i3 = 0;
                } else if (iOrdinal3 == 1) {
                    i3 = 1;
                } else if (iOrdinal3 == 2) {
                    i3 = 2;
                } else if (iOrdinal3 == 3) {
                    i3 = 3;
                } else if (iOrdinal3 == 4) {
                    i3 = 4;
                } else if (Build.VERSION.SDK_INT < 30 || networkType != A.f) {
                    throw new IllegalArgumentException("Could not convert " + networkType + " to int");
                }
                iVar.z(24, i3);
                androidx.work.impl.utils.g requestCompat = c1425f.b;
                Intrinsics.checkNotNullParameter(requestCompat, "requestCompat");
                if (Build.VERSION.SDK_INT < 28) {
                    byteArray = new byte[0];
                } else {
                    NetworkRequest networkRequest = requestCompat.a;
                    if (networkRequest == null) {
                        byteArray = new byte[0];
                    } else {
                        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                        try {
                            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
                            try {
                                int[] iArrE = F2.e(networkRequest);
                                int[] iArrD = F2.d(networkRequest);
                                objectOutputStream.writeInt(iArrE.length);
                                for (int i4 : iArrE) {
                                    objectOutputStream.writeInt(i4);
                                }
                                objectOutputStream.writeInt(iArrD.length);
                                for (int i5 : iArrD) {
                                    objectOutputStream.writeInt(i5);
                                }
                                Unit unit = Unit.a;
                                objectOutputStream.close();
                                byteArrayOutputStream.close();
                                byteArray = byteArrayOutputStream.toByteArray();
                                Intrinsics.checkNotNullExpressionValue(byteArray, "outputStream.toByteArray()");
                            } catch (Throwable th) {
                                try {
                                    throw th;
                                } finally {
                                }
                            }
                        } finally {
                            try {
                                throw th;
                            } finally {
                            }
                        }
                    }
                }
                iVar.E(25, byteArray);
                iVar.z(26, c1425f.c ? 1L : 0L);
                iVar.z(27, c1425f.d ? 1L : 0L);
                iVar.z(28, c1425f.e ? 1L : 0L);
                iVar.z(29, c1425f.f ? 1L : 0L);
                iVar.z(30, c1425f.g);
                iVar.z(31, c1425f.h);
                Set<C1424e> triggers = c1425f.i;
                Intrinsics.checkNotNullParameter(triggers, "triggers");
                if (triggers.isEmpty()) {
                    byteArray2 = new byte[0];
                } else {
                    ByteArrayOutputStream byteArrayOutputStream2 = new ByteArrayOutputStream();
                    try {
                        ObjectOutputStream objectOutputStream2 = new ObjectOutputStream(byteArrayOutputStream2);
                        try {
                            objectOutputStream2.writeInt(triggers.size());
                            for (C1424e c1424e : triggers) {
                                objectOutputStream2.writeUTF(c1424e.a.toString());
                                objectOutputStream2.writeBoolean(c1424e.b);
                            }
                            Unit unit2 = Unit.a;
                            objectOutputStream2.close();
                            byteArrayOutputStream2.close();
                            byteArray2 = byteArrayOutputStream2.toByteArray();
                            Intrinsics.checkNotNullExpressionValue(byteArray2, "outputStream.toByteArray()");
                        } catch (Throwable th2) {
                            try {
                                throw th2;
                            } finally {
                            }
                        }
                    } finally {
                    }
                }
                iVar.E(32, byteArray2);
                return;
            default:
                u uVar = (u) obj;
                iVar.g(1, uVar.a);
                iVar.g(2, uVar.b);
                return;
        }
    }

    public final void p(Object obj) {
        androidx.sqlite.db.framework.i iVarA = a();
        try {
            o(iVarA, obj);
            iVarA.b.executeInsert();
        } finally {
            n(iVarA);
        }
    }
}
