package com.ionspin.kotlin.bignum.integer.base63.array;

import com.ionspin.kotlin.bignum.integer.f;
import java.util.Collection;
import kotlin.A;
import kotlin.B;
import kotlin.C;
import kotlin.D;
import kotlin.E;
import kotlin.Pair;
import kotlin.collections.C4930v;
import kotlin.collections.CollectionsKt;
import kotlin.collections.d0;
import kotlin.collections.unsigned.c;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.l;
import kotlin.z;

/* loaded from: classes2.dex */
public final class b {
    public static final long[] d;
    public static final a f;
    public static final b a = new b();
    public static final long[] b = {0};
    public static final long[] c = {1};
    public static final long[] e = {10};
    public static final E[] g = {new E(new long[]{1}), new E(new long[]{10}), new E(new long[]{100}), new E(new long[]{1000}), new E(new long[]{10000}), new E(new long[]{100000}), new E(new long[]{1000000}), new E(new long[]{10000000}), new E(new long[]{100000000}), new E(new long[]{1000000000}), new E(new long[]{10000000000L}), new E(new long[]{100000000000L}), new E(new long[]{1000000000000L}), new E(new long[]{10000000000000L}), new E(new long[]{100000000000000L}), new E(new long[]{1000000000000000L}), new E(new long[]{10000000000000000L}), new E(new long[]{100000000000000000L}), new E(new long[]{1000000000000000000L}), new E(new long[]{776627963145224192L, 1}), new E(new long[]{7766279631452241920L, 10}), new E(new long[]{3875820019684212736L, 108}), new E(new long[]{1864712049423024128L, 1084}), new E(new long[]{200376420520689664L, 10842}), new E(new long[]{2003764205206896640L, 108420}), new E(new long[]{1590897978359414784L, 1084202}), new E(new long[]{6685607746739372032L, 10842021}), new E(new long[]{2292473209410289664L, 108420217}), new E(new long[]{4477988020393345024L, 1084202172}), new E(new long[]{7886392056514347008L, 10842021724L}), new E(new long[]{5076944270305263616L, 108420217248L}), new E(new long[]{4652582518778757120L, 1084202172485L}), new E(new long[]{408965003513692160L, 10842021724855L}), new E(new long[]{4089650035136921600L, 108420217248550L}), new E(new long[]{4003012203950112768L, 1084202172485504L}), new E(new long[]{3136633892082024448L, 10842021724855044L}), new E(new long[]{3696222810255917056L, 108420217248550443L}), new E(new long[]{68739955140067328L, 1084202172485504434L}), new E(new long[]{687399551400673280L, 1618649688000268532L, 1}), new E(new long[]{6873995514006732800L, 6963124843147909512L, 11}), new E(new long[]{4176350882083897344L, 5067644173495664471L, 117}), new E(new long[]{4870020673419870208L, 4559581550682765674L, 1175}), new E(new long[]{2583346549924823040L, 8702327359408553513L, 11754}), new E(new long[]{7386721425538678784L, 4012925262392552860L, 117549}), new E(new long[]{80237960548581376L, 3235764476506425376L, 1175494}), new E(new long[]{802379605485813760L, 4687528654499926336L, 11754943}), new E(new long[]{8023796054858137600L, 758426360725384320L, 117549435}), new E(new long[]{6450984253743169536L, 7584263607253843208L, 1175494350}), new E(new long[]{9169610316303040512L, 2055659777700225622L, 11754943508L}), new E(new long[]{8685754831337422848L, 2109853703292704613L, 117549435082L}), new E(new long[]{3847199981681246208L, 2651792959217494523L, 1175494350822L}), new E(new long[]{1578511669393358848L, 8071185518465393618L, 11754943508222L}), new E(new long[]{6561744657078812672L, 6924878889815729717L, 117549435082228L}), new E(new long[]{1053842312804696064L, 4685184640173866521L, 1175494350822287L}), new E(new long[]{1315051091192184832L, 734986217464786171L, 11754943508222875L}), new E(new long[]{3927138875067072512L, 7349862174647861711L, 117549435082228750L}), new E(new long[]{2377900603251621888L, 8935017488495186458L, 1175494350822287507L}), new E(new long[]{5332261958806667264L, 6339826553258882310L, 2531571471368099271L, 1}), new E(new long[]{7205759403792793600L, 8058033311460168257L, 6868970639971441100L, 12}), new E(new long[]{7493989779944505344L, 6793356819763476113L, 4126102141730980352L, 127}), new E(new long[]{1152921504606846976L, 3369963939651330482L, 4367533269890700295L, 1274}), new E(new long[]{2305843009213693952L, 6029523285948977397L, 6781844551487899721L, 12744}), new E(new long[]{4611686018427387904L, 4955000638361119124L, 3254841256895566560L, 127447}), new E(new long[]{0, 3433146199337312205L, 4878296458391338181L, 1274473}), new E(new long[]{0, 6661345882808794626L, 2666104399639502773L, 12744735}), new E(new long[]{0, 2049854570104515604L, 8214299922685476121L, 127447352}), new E(new long[]{0, 2051801627335604424L, 8356022932016554748L, 1274473528}), new E(new long[]{0, 2071272199646492624L, 549880988472565210L, 12744735289L}), new E(new long[]{0, 2265977922755374624L, 5498809884725652102L, 127447352890L}), new E(new long[]{0, 4213035153844194624L, 8871238662982641982L, 1274473528905L}), new E(new long[]{0, 5236863391022843008L, 5702038298133437552L, 12744735289059L}), new E(new long[]{0, 6251773725954551040L, 1680150760205720677L, 127447352890596L}), new E(new long[]{0, 7177505038416855552L, 7578135565202430968L, 1274473528905961L}), new E(new long[]{0, 7211446126185124864L, 1994379357186103223L, 12744735289059618L}), new E(new long[]{0, 7550857003867817984L, 1497049498151480621L, 127447352890596182L}), new E(new long[]{0, 1721593743839973376L, 5747122944660030410L, 1274473528905961821L}), new E(new long[]{0, 7992565401544957952L, 2130997225471649253L, 3521363252204842408L, 1}), new E(new long[]{0, 6138677720611373056L, 2863228181006940922L, 7543516411484096658L, 13}), new E(new long[]{0, 6046544984985075712L, 962165699505081802L, 1648187820002760119L, 138}), new E(new long[]{0, 5125217628722102272L, 398284958196042218L, 7258506163172825383L, 1381}), new E(new long[]{0, 5135316102947143680L, 3982849581960422185L, 8021457373744823174L, 13817}), new E(new long[]{0, 5236300845197557760L, 2935007672185118623L, 6427597442610025280L, 138178}), new E(new long[]{0, 6246148267701698560L, 1679960611286858811L, 8935742204971597955L, 1381786}), new E(new long[]{0, 7121250455888330752L, 7576234076013812308L, 6347073718022997279L, 13817869}), new E(new long[]{0, 6648900300899876864L, 1975364465299916623L, 8130504959101317950L, 138178696}), new E(new long[]{0, 1925398751015337984L, 1306900579289614621L, 7518073296174973038L, 1381786968}), new E(new long[]{0, 807243436443828224L, 3845633756041370404L, 1393756666911523917L, 13817869688L}), new E(new long[]{0, 8072434364438282240L, 1562849412994600808L, 4714194632260463366L, 138178696881L}), new E(new long[]{0, 6937367349544615936L, 6405122093091232280L, 1025086138330754621L, 1381786968815L}), new E(new long[]{0, 4810069237462728704L, 8710988709783667959L, 1027489346452770408L, 13817869688151L}), new E(new long[]{0, 1983832190353408000L, 4099538766143697323L, 1051521427672928281L, 138178696881511L}), new E(new long[]{0, 1391577829824528384L, 4101899514017870000L, 1291842239874507006L, 1381786968815111L}), new E(new long[]{0, 4692406261390508032L, 4125506992759596769L, 3695050361890294256L, 13817869688151111L}), new E(new long[]{0, 807202429631201280L, 4361581780176864463L, 57015471483839332L, 138178696881511114L}), new E(new long[]{0, 8072024296312012800L, 6722329654349541398L, 570154714838393324L, 1381786968815111140L}), new E(new long[]{0, 6933266668281921536L, 2659692285511983332L, 5701547148383933247L, 4594497651296335592L, 1}), new E(new long[]{0, 4769062424835784704L, 8150178781410281711L, 1675239262710677624L, 9051488365544252694L, 14}), new E(new long[]{0, 1573764064083968000L, 7714811519264610651L, 7529020590252000440L, 7504535323749544669L, 149}), new E(new long[]{0, 6514268603984904192L, 3361138897807900047L, 1503229607681797944L, 1258376942657240234L, 1498}), new E(new long[]{0, 579081781865611264L, 5941272867514673053L, 5808924039963203635L, 3360397389717626533L, 14981}), new E(new long[]{0, 5790817818656112640L, 4072496454018075682L, 2749008178503381508L, 5933857786611937912L, 149813})};

    static {
        long[] jArr = {2};
        d = jArr;
        f = new a(jArr, true);
    }

    public static a b(a receiver, long[] mask) {
        Intrinsics.checkNotNullParameter(receiver, "$receiver");
        Intrinsics.checkNotNullParameter(mask, "operand");
        long[] operand = receiver.a;
        Intrinsics.checkNotNullParameter(operand, "operand");
        Intrinsics.checkNotNullParameter(mask, "mask");
        Pair pair = operand.length > mask.length ? new Pair(new E(operand), new E(mask)) : new Pair(new E(mask), new E(operand));
        ((E) pair.a).getClass();
        int length = ((E) pair.b).a.length;
        long[] storage = new long[length];
        for (int i = 0; i < length; i++) {
            long j = operand[i];
            C c2 = D.b;
            storage[i] = j & mask[i];
        }
        Intrinsics.checkNotNullParameter(storage, "storage");
        return new a(storage, receiver.b);
    }

    public static int g(long[] first, long[] second, int i, int i2) {
        boolean z;
        boolean z2;
        Intrinsics.checkNotNullParameter(first, "first");
        Intrinsics.checkNotNullParameter(second, "second");
        if (i <= i2) {
            if (i2 <= i) {
                int i3 = i - 1;
                while (true) {
                    if (i3 < 0) {
                        z = false;
                        z2 = true;
                        break;
                    }
                    long j = first[i3];
                    C c2 = D.b;
                    if (Long.compareUnsigned(j, second[i3]) > 0) {
                        z2 = false;
                        z = true;
                        break;
                    }
                    if (Long.compareUnsigned(first[i3], second[i3]) < 0) {
                        z2 = false;
                        z = false;
                        break;
                    }
                    i3--;
                }
                if (z2) {
                    return 0;
                }
                if (z) {
                }
            }
            return -1;
        }
        return 1;
    }

    public static int h(long[] bigInteger) {
        Intrinsics.checkNotNullParameter(bigInteger, "bigInteger");
        int length = bigInteger.length - 1;
        if (length <= 0) {
            return 0;
        }
        long j = bigInteger[length];
        C c2 = D.b;
        while (j == 0 && length > 0) {
            length--;
            j = bigInteger[length];
            C c3 = D.b;
        }
        long j2 = bigInteger[length];
        C c4 = D.b;
        if (j2 == 0) {
            length--;
        }
        return (bigInteger.length - length) - 1;
    }

    public static long[] j(long[] original, int i) {
        long j;
        Intrinsics.checkNotNullParameter(original, "original");
        int length = original.length + i;
        long[] storage = new long[length];
        for (int i2 = 0; i2 < length; i2++) {
            if (i2 < original.length) {
                j = original[i2];
                C c2 = D.b;
            } else {
                j = 0;
            }
            storage[i2] = j;
        }
        Intrinsics.checkNotNullParameter(storage, "storage");
        return storage;
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0019  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static boolean k(long[] r7) {
        /*
            long[] r0 = com.ionspin.kotlin.bignum.integer.base63.array.b.b
            boolean r0 = kotlin.jvm.internal.Intrinsics.b(r7, r0)
            r1 = 1
            if (r0 == 0) goto La
            goto L21
        La:
            int r0 = r7.length
            r2 = 0
            if (r0 != r1) goto L19
            r3 = r7[r2]
            kotlin.C r0 = kotlin.D.b
            r5 = 0
            int r0 = (r3 > r5 ? 1 : (r3 == r5 ? 0 : -1))
            if (r0 != 0) goto L19
            goto L21
        L19:
            int r0 = r7.length
            int r7 = h(r7)
            int r0 = r0 - r7
            if (r0 != 0) goto L22
        L21:
            return r1
        L22:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.ionspin.kotlin.bignum.integer.base63.array.b.k(long[]):boolean");
    }

    public static int o(long j) {
        int i;
        long j2 = j >>> 32;
        C c2 = D.b;
        if (j2 != 0) {
            i = 31;
            j = j2;
        } else {
            i = 63;
        }
        long j3 = j >>> 16;
        if (j3 != 0) {
            i -= 16;
            j = j3;
        }
        long j4 = j >>> 8;
        if (j4 != 0) {
            i -= 8;
            j = j4;
        }
        long j5 = j >>> 4;
        if (j5 != 0) {
            i -= 4;
            j = j5;
        }
        long j6 = j >>> 2;
        if (j6 != 0) {
            i -= 2;
            j = j6;
        }
        return (j >>> 1) != 0 ? i - 2 : i - ((int) j);
    }

    public static long[] r(long[] bigInteger) {
        Intrinsics.checkNotNullParameter(bigInteger, "bigInteger");
        int length = bigInteger.length - h(bigInteger);
        if (length == 0) {
            return b;
        }
        if (bigInteger.length == length) {
            return bigInteger;
        }
        if (bigInteger.length - length > 1000) {
            StringBuilder sb = new StringBuilder("RLZ original array : ");
            sb.append(bigInteger.length);
            sb.append(" contains: ");
            sb.append((bigInteger.length - length) - 1);
            sb.append(" zeros");
            System.out.println((Object) sb.toString());
        }
        long[] storage = C4930v.m(bigInteger, 0, length);
        Intrinsics.checkNotNullParameter(storage, "storage");
        return storage;
    }

    public static a s(a aVar, int i) {
        Intrinsics.checkNotNullParameter(aVar, "<this>");
        return new a(t(aVar.a, i), aVar.b);
    }

    public static long[] t(long[] operand, int i) {
        int iH;
        long j;
        long j2;
        Intrinsics.checkNotNullParameter(operand, "$receiver");
        Intrinsics.checkNotNullParameter(operand, "operand");
        if (k(operand) || i == 0) {
            return operand;
        }
        int i2 = 0;
        boolean z = operand.length == 0;
        long[] jArr = b;
        if (z || operand.length == (iH = h(operand))) {
            return jArr;
        }
        int length = operand.length - iH;
        long j3 = operand[length - 1];
        C c2 = D.b;
        int iO = o(j3);
        int i3 = i / 63;
        int i4 = i % 63;
        int i5 = i4 > iO ? i3 + 1 : i3;
        if (i4 == 0) {
            int i6 = length + i5;
            long[] storage = new long[i6];
            while (i2 < i6) {
                if (i2 < 0 || i2 >= i3) {
                    j2 = operand[i2 - i3];
                    C c3 = D.b;
                } else {
                    j2 = 0;
                }
                storage[i2] = j2;
                i2++;
            }
            Intrinsics.checkNotNullParameter(storage, "storage");
            return storage;
        }
        int i7 = length + i5;
        long[] storage2 = new long[i7];
        while (i2 < i7) {
            if (i2 >= 0 && i2 < i3) {
                j = 0;
            } else if (i2 == i3) {
                long j4 = operand[i2 - i3];
                C c4 = D.b;
                j = Long.MAX_VALUE & (j4 << i4);
            } else {
                int i8 = i3 + 1;
                if (i2 < length + i3 && i8 <= i2) {
                    int i9 = i2 - i3;
                    long j5 = operand[i9];
                    C c5 = D.b;
                    j = (Long.MAX_VALUE & (j5 << i4)) | (operand[i9 - 1] >>> (63 - i4));
                } else {
                    if (i2 != i7 - 1) {
                        throw new RuntimeException(Intrinsics.k(Integer.valueOf(i2), "Invalid case "));
                    }
                    long j6 = operand[i2 - i5];
                    C c6 = D.b;
                    j = j6 >>> (63 - i4);
                }
            }
            storage2[i2] = j;
            i2++;
        }
        Intrinsics.checkNotNullParameter(storage2, "storage");
        return storage2;
    }

    public static a u(a aVar, int i) {
        Intrinsics.checkNotNullParameter(aVar, "<this>");
        return new a(v(aVar.a, i), aVar.b);
    }

    public static long[] v(long[] operand, int i) {
        long j;
        Intrinsics.checkNotNullParameter(operand, "$receiver");
        Intrinsics.checkNotNullParameter(operand, "operand");
        if (operand.length == 0 || i == 0) {
            return operand;
        }
        int length = operand.length - h(operand);
        int i2 = i % 63;
        int i3 = i / 63;
        long[] jArr = b;
        if (i3 < length) {
            if (i2 == 0) {
                Intrinsics.checkNotNullParameter(C4930v.m(operand, length - i3, length), "storage");
            }
            if (length > 1 && length - i3 == 1) {
                long j2 = operand[length - 1];
                C c2 = D.b;
                return new long[]{j2 >>> i2};
            }
            int i4 = length - i3;
            if (i4 != 0) {
                long[] storage = new long[i4];
                for (int i5 = 0; i5 < i4; i5++) {
                    if (i5 >= 0 && i5 < (length - 1) - i3) {
                        int i6 = i5 + i3;
                        long j3 = operand[i6];
                        C c3 = D.b;
                        j = (j3 >>> i2) | ((operand[i6 + 1] << (63 - i2)) & Long.MAX_VALUE);
                    } else {
                        if (i5 != (length - 1) - i3) {
                            throw new RuntimeException(Intrinsics.k(Integer.valueOf(i5), "Invalid case "));
                        }
                        long j4 = operand[i5 + i3];
                        C c4 = D.b;
                        j = j4 >>> i2;
                    }
                    storage[i5] = j;
                }
                Intrinsics.checkNotNullParameter(storage, "storage");
                return storage;
            }
        }
        return jArr;
    }

    public final long[] A(long[] operand, long[] mask) {
        long j;
        Intrinsics.checkNotNullParameter(operand, "operand");
        Intrinsics.checkNotNullParameter(mask, "mask");
        if (operand.length < mask.length) {
            return A(mask, operand);
        }
        int length = operand.length;
        long[] storage = new long[length];
        for (int i = 0; i < length; i++) {
            if (i < mask.length) {
                long j2 = operand[i];
                C c2 = D.b;
                j = j2 ^ mask[i];
            } else {
                j = operand[i];
                C c3 = D.b;
            }
            storage[i] = j;
        }
        Intrinsics.checkNotNullParameter(storage, "storage");
        return r(storage);
    }

    public final long[] a(long[] first, long[] second) {
        long[] storage;
        long[] jArr;
        Intrinsics.checkNotNullParameter(first, "first");
        Intrinsics.checkNotNullParameter(second, "second");
        if (k(first)) {
            return second;
        }
        if (k(second)) {
            return first;
        }
        int length = first.length - h(first);
        int length2 = second.length - h(second);
        f fVar = length > length2 ? new f(Integer.valueOf(first.length), Integer.valueOf(second.length), new E(first), new E(second), Integer.valueOf(length), Integer.valueOf(length2)) : new f(Integer.valueOf(second.length), Integer.valueOf(first.length), new E(second), new E(first), Integer.valueOf(length2), Integer.valueOf(length));
        int iIntValue = fVar.a.intValue();
        E e2 = fVar.c;
        E e3 = fVar.d;
        int iIntValue2 = fVar.e.intValue();
        int iIntValue3 = fVar.f.intValue();
        long j = e2.a[iIntValue2 - 1];
        C c2 = D.b;
        long j2 = j & 6917529027641081856L;
        int i = 0;
        boolean z = (j2 == 0 && (e3.a[iIntValue3 - 1] & 6917529027641081856L) == 0) ? false : true;
        if (z) {
            int i2 = iIntValue + 1;
            storage = new long[i2];
            for (int i3 = 0; i3 < i2; i3++) {
                storage[i3] = 0;
            }
            Intrinsics.checkNotNullParameter(storage, "storage");
        } else {
            storage = new long[iIntValue];
            for (int i4 = 0; i4 < iIntValue; i4++) {
                storage[i4] = 0;
            }
            Intrinsics.checkNotNullParameter(storage, "storage");
        }
        Intrinsics.checkNotNullParameter(storage, "resultArray");
        Intrinsics.checkNotNullParameter(first, "first");
        Intrinsics.checkNotNullParameter(second, "second");
        if (k(first)) {
            C4930v.g(first, storage, 0, 0, first.length);
        } else if (k(second)) {
            C4930v.g(second, storage, 0, 0, second.length);
        } else {
            int length3 = first.length - h(first);
            int length4 = second.length - h(second);
            f fVar2 = length3 > length4 ? new f(Integer.valueOf(first.length), Integer.valueOf(second.length), new E(first), new E(second), Integer.valueOf(length3), Integer.valueOf(length4)) : new f(Integer.valueOf(second.length), Integer.valueOf(first.length), new E(second), new E(first), Integer.valueOf(length4), Integer.valueOf(length3));
            int iIntValue4 = fVar2.a.intValue();
            E e4 = fVar2.c;
            E e5 = fVar2.d;
            int iIntValue5 = fVar2.e.intValue();
            int iIntValue6 = fVar2.f.intValue();
            long j3 = 0;
            while (true) {
                jArr = e4.a;
                if (i >= iIntValue6) {
                    break;
                }
                long j4 = jArr[i];
                C c3 = D.b;
                long j5 = j3 + j4 + e5.a[i];
                storage[i] = Long.MAX_VALUE & j5;
                j3 = j5 >>> 63;
                i++;
            }
            while (true) {
                if (j3 == 0) {
                    while (i < iIntValue5) {
                        long j6 = jArr[i];
                        C c4 = D.b;
                        storage[i] = j6;
                        i++;
                    }
                } else {
                    if (i == iIntValue4) {
                        storage[iIntValue4] = j3;
                        break;
                    }
                    long j7 = jArr[i];
                    C c5 = D.b;
                    long j8 = j3 + j7;
                    storage[i] = j8 & Long.MAX_VALUE;
                    j3 = j8 >>> 63;
                    i++;
                }
            }
        }
        return z ? r(storage) : storage;
    }

    public final long[] c(int i, long j, long[] first) {
        Intrinsics.checkNotNullParameter(first, "first");
        long j2 = j & 4294967295L;
        C c2 = D.b;
        long j3 = j >>> 32;
        int iO = (63 - o(j)) + d(first);
        long[] jArrA = E.a(iO % 63 != 0 ? (iO / 63) + 1 : iO / 63);
        int i2 = 0;
        int i3 = 0;
        long j4 = 0;
        while (i2 < i) {
            long j5 = first[i2];
            C c3 = D.b;
            long j6 = j5 & 4294967295L;
            long j7 = j5 >>> 32;
            i2++;
            long j8 = j6 * j2;
            long j9 = j4 + (j8 & Long.MAX_VALUE);
            long j10 = (j8 >>> 63) + (j9 >>> 63);
            long j11 = (j2 * j7) + (j6 * j3);
            long j12 = (j9 & Long.MAX_VALUE) + ((j11 << 32) & Long.MAX_VALUE);
            jArrA[i3] = j12 & Long.MAX_VALUE;
            j4 = j10 + (j11 >>> 31) + (j12 >>> 63) + ((j7 * j3) << 1);
            i3++;
        }
        if (j4 != 0) {
            jArrA[i3] = j4;
        }
        return jArrA;
    }

    public final int d(long[] value) {
        Intrinsics.checkNotNullParameter(value, "value");
        if (k(value)) {
            return 0;
        }
        int length = (value.length - h(value)) - 1;
        long j = value[length];
        C c2 = D.b;
        return (length * 63) + (63 - o(j));
    }

    public final int e(long[] first, long[] second) {
        Intrinsics.checkNotNullParameter(first, "first");
        Intrinsics.checkNotNullParameter(second, "second");
        return g(first, second, first.length - h(first), second.length - h(second));
    }

    public final int f(long[] receiver, long[] other) {
        Intrinsics.checkNotNullParameter(receiver, "$receiver");
        Intrinsics.checkNotNullParameter(other, "other");
        return e(receiver, other);
    }

    /* JADX WARN: Removed duplicated region for block: B:144:0x04d6  */
    /* JADX WARN: Removed duplicated region for block: B:145:0x04db  */
    /* JADX WARN: Removed duplicated region for block: B:179:0x05fc A[LOOP:3: B:156:0x0508->B:179:0x05fc, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:182:0x0618  */
    /* JADX WARN: Removed duplicated region for block: B:183:0x061d  */
    /* JADX WARN: Removed duplicated region for block: B:187:0x063a A[LOOP:1: B:185:0x0634->B:187:0x063a, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:191:0x0657 A[LOOP:0: B:21:0x00e2->B:191:0x0657, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:199:0x0654 A[EDGE_INSN: B:199:0x0654->B:190:0x0654 BREAK  A[LOOP:0: B:21:0x00e2->B:191:0x0657], SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:202:0x0601 A[EDGE_INSN: B:202:0x0601->B:180:0x0601 BREAK  A[LOOP:3: B:156:0x0508->B:179:0x05fc], SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:203:0x02ee A[EDGE_INSN: B:203:0x02ee->B:76:0x02ee BREAK  A[LOOP:4: B:45:0x022a->B:77:0x02f1], SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:68:0x02be  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x02c0  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x02d5 A[LOOP:5: B:71:0x02cf->B:73:0x02d5, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:77:0x02f1 A[LOOP:4: B:45:0x022a->B:77:0x02f1, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:87:0x0332  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final kotlin.Pair i(long[] r47, long[] r48) {
        /*
            Method dump skipped, instructions count: 1708
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.ionspin.kotlin.bignum.integer.base63.array.b.i(long[], long[]):kotlin.Pair");
    }

    public final a l(a aVar, a other) {
        Intrinsics.checkNotNullParameter(aVar, "<this>");
        Intrinsics.checkNotNullParameter(other, "other");
        boolean z = !other.b;
        long[] other2 = other.a;
        Intrinsics.checkNotNullParameter(other2, "unsignedValue");
        boolean z2 = aVar.b;
        boolean z3 = z2 ^ z;
        long[] receiver = aVar.a;
        if (z3) {
            return f(receiver, other2) > 0 ? new a(m(receiver, other2), z2) : new a(m(other2, receiver), z);
        }
        Intrinsics.checkNotNullParameter(receiver, "$receiver");
        Intrinsics.checkNotNullParameter(other2, "other");
        return new a(a(receiver, other2), z2);
    }

    public final long[] m(long[] receiver, long[] other) {
        Intrinsics.checkNotNullParameter(receiver, "$receiver");
        Intrinsics.checkNotNullParameter(other, "other");
        return w(receiver, other);
    }

    public final long[] n(long[] first, long[] secondUnchecked) {
        boolean z;
        Collection e2;
        Collection e3;
        boolean z2 = true;
        Intrinsics.checkNotNullParameter(first, "first");
        Intrinsics.checkNotNullParameter(secondUnchecked, "second");
        int length = first.length - h(first);
        int length2 = secondUnchecked.length - h(secondUnchecked);
        boolean zK = k(first);
        long[] receiver = b;
        if (zK || k(secondUnchecked)) {
            return receiver;
        }
        if ((length >= 120 || length2 >= 120) && (length <= 15000 || length2 < 15000)) {
            a aVar = new a(first, true);
            a aVar2 = new a(secondUnchecked, true);
            int iMax = (Math.max(length, length2) + 1) / 2;
            int i = iMax * 63;
            long[] receiver2 = t(c, i);
            Intrinsics.checkNotNullParameter(receiver2, "$receiver");
            long[] jArrW = w(receiver2, new long[]{1});
            a aVarB = b(aVar, jArrW);
            a aVarU = u(aVar, i);
            a aVarB2 = b(aVar2, jArrW);
            a aVarU2 = u(aVar2, i);
            a aVarX = x(aVarU, aVarU2);
            a aVarX2 = x(aVarB, aVarB2);
            return q(q(s(aVarX, 126 * iMax), s(l(l(x(q(aVarU, aVarB), q(aVarU2, aVarB2)), aVarX), aVarX2), i)), aVarX2).a;
        }
        if (length < 15000 || length2 < 15000) {
            int length3 = secondUnchecked.length;
            int i2 = 0;
            int i3 = 0;
            while (i2 < length3) {
                long j = secondUnchecked[i2];
                int i4 = i3 + 1;
                if (i3 > length2) {
                    z = z2;
                } else {
                    b bVar = a;
                    Intrinsics.checkNotNullParameter(first, "first");
                    z = z2;
                    long[] other = t(bVar.c(first.length - h(first), j, first), i3 * 63);
                    Intrinsics.checkNotNullParameter(receiver, "$receiver");
                    Intrinsics.checkNotNullParameter(other, "other");
                    receiver = bVar.a(receiver, other);
                }
                i2++;
                i3 = i4;
                z2 = z;
            }
            return receiver;
        }
        Intrinsics.checkNotNullParameter(first, "firstUnchecked");
        Intrinsics.checkNotNullParameter(secondUnchecked, "secondUnchecked");
        if (first.length % 3 != 0) {
            E e4 = new E(first);
            int length4 = (((first.length + 2) / 3) * 3) - first.length;
            long[] storage = new long[length4];
            for (int i5 = 0; i5 < length4; i5++) {
                storage[i5] = 0;
            }
            Intrinsics.checkNotNullParameter(storage, "storage");
            e2 = CollectionsKt.c0(e4, new E(storage));
        } else {
            e2 = new E(first);
        }
        long[] jArrA = d0.a(e2);
        if (secondUnchecked.length % 3 != 0) {
            E e5 = new E(secondUnchecked);
            int length5 = (((secondUnchecked.length + 2) / 3) * 3) - secondUnchecked.length;
            long[] storage2 = new long[length5];
            for (int i6 = 0; i6 < length5; i6++) {
                storage2[i6] = 0;
            }
            Intrinsics.checkNotNullParameter(storage2, "storage");
            e3 = CollectionsKt.c0(e5, new E(storage2));
        } else {
            e3 = new E(secondUnchecked);
        }
        long[] jArrA2 = d0.a(e3);
        int length6 = jArrA.length;
        int length7 = jArrA2.length;
        Pair pair = length6 > length7 ? new Pair(new E(jArrA), new E(j(jArrA2, length6 - length7))) : length6 < length7 ? new Pair(new E(j(jArrA, length7 - length6)), new E(jArrA2)) : new Pair(new E(jArrA), new E(jArrA2));
        long[] jArr = ((E) pair.a).a;
        long[] jArr2 = ((E) pair.b).a;
        int iMax2 = (Math.max(jArrA.length, jArrA2.length) + 2) / 3;
        a aVar3 = new a(d0.a(c.a(jArr, l.h(0, iMax2))), true);
        int i7 = iMax2 * 2;
        a aVar4 = new a(d0.a(c.a(jArr, l.h(iMax2, i7))), true);
        int i8 = iMax2 * 3;
        a aVar5 = new a(d0.a(c.a(jArr, l.h(i7, i8))), true);
        a aVar6 = new a(d0.a(c.a(jArr2, l.h(0, iMax2))), true);
        a aVar7 = new a(d0.a(c.a(jArr2, l.h(iMax2, i7))), true);
        a aVar8 = new a(d0.a(c.a(jArr2, l.h(i7, i8))), true);
        a aVarQ = q(aVar3, aVar5);
        a aVarQ2 = q(aVarQ, aVar4);
        a aVarL = l(aVarQ, aVar4);
        a aVarQ3 = q(aVarL, aVar5);
        a aVar9 = f;
        a aVarL2 = l(x(aVarQ3, aVar9), aVar3);
        a aVarQ4 = q(aVar6, aVar8);
        a aVarQ5 = q(aVarQ4, aVar7);
        a aVarL3 = l(aVarQ4, aVar7);
        a aVarL4 = l(x(q(aVarL3, aVar8), aVar9), aVar6);
        a aVarX3 = x(aVar3, aVar6);
        a aVarX4 = x(aVarQ2, aVarQ5);
        a aVarX5 = x(aVarL, aVarL3);
        a aVarX6 = x(aVarL2, aVarL4);
        a aVarX7 = x(aVar5, aVar8);
        a aVarL5 = l(aVarX6, aVarX4);
        long[] other2 = {3};
        a other3 = new a(other2, true);
        Intrinsics.checkNotNullParameter(aVarL5, "<this>");
        Intrinsics.checkNotNullParameter(other3, "other");
        long[] receiver3 = aVarL5.a;
        Intrinsics.checkNotNullParameter(receiver3, "$receiver");
        Intrinsics.checkNotNullParameter(other2, "other");
        a aVar10 = new a(((E) i(receiver3, other2).a).a, aVarL5.b);
        a aVarU3 = u(l(aVarX4, aVarX5), 1);
        a aVarL6 = l(aVarX5, aVarX3);
        a aVarQ6 = q(u(l(aVarL6, aVar10), 1), x(aVar9, aVarX7));
        return q(q(q(q(aVarX3, s(l(aVarU3, aVarQ6), iMax2 * 63)), s(l(q(aVarL6, aVarU3), aVarX7), iMax2 * 126)), s(aVarQ6, iMax2 * 189)), s(aVarX7, iMax2 * 252)).a;
    }

    public final long[] p(String number) {
        char c2;
        int i;
        Intrinsics.checkNotNullParameter(number, "number");
        long[] first = b;
        String lowerCase = number.toLowerCase();
        Intrinsics.checkNotNullExpressionValue(lowerCase, "(this as java.lang.String).toLowerCase()");
        for (int i2 = 0; i2 < lowerCase.length(); i2++) {
            char cCharAt = lowerCase.charAt(i2);
            b bVar = a;
            C c3 = D.b;
            Intrinsics.checkNotNullParameter(first, "$receiver");
            Intrinsics.checkNotNullParameter(first, "first");
            long[] receiver = bVar.c(first.length - h(first), 10, first);
            if ('0' <= cCharAt && cCharAt <= '9') {
                i = (char) (cCharAt - '0');
            } else if ('a' <= cCharAt && cCharAt <= 'z') {
                i = cCharAt - 'W';
            } else if ('A' > cCharAt || cCharAt > 'Z') {
                if (65313 <= cCharAt && cCharAt <= 65338) {
                    c2 = 65323;
                } else {
                    if (65345 > cCharAt || cCharAt > 65370) {
                        if (cCharAt != '.') {
                            throw new NumberFormatException(Intrinsics.k(Character.valueOf(cCharAt), "Invalid digit for radix "));
                        }
                        throw new NumberFormatException("Invalid digit for radix " + cCharAt + " (Possibly a decimal value, which is not supported by BigInteger parser");
                    }
                    c2 = 65355;
                }
                i = cCharAt - c2;
            } else {
                i = cCharAt - '7';
            }
            if (i < 0 || i >= 10) {
                throw new NumberFormatException(cCharAt + " is not a valid digit for number system with base 10");
            }
            Intrinsics.checkNotNullParameter(receiver, "$receiver");
            first = bVar.a(receiver, new long[]{i});
        }
        return r(first);
    }

    public final a q(a aVar, a other) {
        Intrinsics.checkNotNullParameter(aVar, "<this>");
        Intrinsics.checkNotNullParameter(other, "other");
        boolean z = aVar.b;
        boolean z2 = other.b;
        boolean z3 = z ^ z2;
        long[] receiver = aVar.a;
        long[] other2 = other.a;
        if (z3) {
            return f(receiver, other2) > 0 ? new a(m(receiver, other2), z) : new a(m(other2, receiver), z2);
        }
        Intrinsics.checkNotNullParameter(receiver, "$receiver");
        Intrinsics.checkNotNullParameter(other2, "other");
        return new a(a(receiver, other2), z);
    }

    /* JADX WARN: Code restructure failed: missing block: B:33:0x00e2, code lost:
    
        if (r0 == 0) goto L34;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final long[] w(long[] r22, long[] r23) {
        /*
            Method dump skipped, instructions count: 242
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.ionspin.kotlin.bignum.integer.base63.array.b.w(long[], long[]):long[]");
    }

    public final a x(a aVar, a other) {
        Intrinsics.checkNotNullParameter(aVar, "<this>");
        Intrinsics.checkNotNullParameter(other, "other");
        return new a(y(aVar.a, other.a), !(aVar.b ^ other.b));
    }

    public final long[] y(long[] receiver, long[] other) {
        Intrinsics.checkNotNullParameter(receiver, "$receiver");
        Intrinsics.checkNotNullParameter(other, "other");
        return n(receiver, other);
    }

    public final int[] z(long[] operand) {
        long[] jArrR;
        Intrinsics.checkNotNullParameter(operand, "$receiver");
        Intrinsics.checkNotNullParameter(operand, "operand");
        Intrinsics.checkNotNullParameter(operand, "operand");
        int i = 0;
        if (k(operand)) {
            jArrR = b;
        } else {
            int iD = d(operand);
            int i2 = iD % 64 == 0 ? iD / 64 : (iD / 64) + 1;
            long[] jArrA = E.a(i2);
            if (i2 > 0) {
                int i3 = 0;
                while (true) {
                    int i4 = i3 + 1;
                    int i5 = i3 % 63;
                    int i6 = (i3 / 63) + i3;
                    int i7 = i6 + 1;
                    if (i7 < operand.length) {
                        long j = operand[i6];
                        C c2 = D.b;
                        jArrA[i3] = (operand[i7] << (63 - i5)) | (j >>> i5);
                    } else {
                        long j2 = operand[i6];
                        C c3 = D.b;
                        jArrA[i3] = j2 >>> i5;
                    }
                    if (i4 >= i2) {
                        break;
                    }
                    i3 = i4;
                }
            }
            jArrR = r(jArrA);
        }
        int[] iArrA = B.a(jArrR.length * 2);
        int length = jArrR.length;
        if (length > 0) {
            while (true) {
                int i8 = i + 1;
                int i9 = i * 2;
                long j3 = jArrR[i];
                C c4 = D.b;
                int[] iArr = com.ionspin.kotlin.bignum.integer.base32.a.a;
                z zVar = A.b;
                iArrA[i9] = (int) ((-1) & 4294967295L & j3);
                iArrA[i9 + 1] = (int) (j3 >>> 32);
                if (i8 >= length) {
                    break;
                }
                i = i8;
            }
        }
        return com.ionspin.kotlin.bignum.integer.base32.a.g(iArrA);
    }
}
