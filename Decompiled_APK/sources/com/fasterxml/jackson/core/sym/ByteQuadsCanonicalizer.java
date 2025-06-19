package com.fasterxml.jackson.core.sym;

import android.support.v4.media.session.a;
import androidx.compose.animation.d0;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.exc.StreamConstraintsException;
import com.fasterxml.jackson.core.util.InternCache;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes.dex */
public final class ByteQuadsCanonicalizer {
    protected int _count;
    protected final boolean _failOnDoS;
    protected int[] _hashArea;
    protected boolean _hashShared;
    protected int _hashSize;
    protected final InternCache _interner;
    protected int _longNameOffset;
    protected String[] _names;
    protected final ByteQuadsCanonicalizer _parent;
    protected int _secondaryStart;
    protected final int _seed;
    protected int _spilloverEnd;
    protected final AtomicReference<TableInfo> _tableInfo;
    protected int _tertiaryShift;
    protected int _tertiaryStart;

    private ByteQuadsCanonicalizer(int i, int i2) {
        this._parent = null;
        this._count = 0;
        this._hashShared = true;
        this._seed = i2;
        this._interner = null;
        this._failOnDoS = true;
        int i3 = 16;
        if (i < 16) {
            i = i3;
        } else if (((i - 1) & i) != 0) {
            while (i3 < i) {
                i3 += i3;
            }
            i = i3;
        }
        this._tableInfo = new AtomicReference<>(TableInfo.createInitial(i));
    }

    private int _appendLongName(int[] iArr, int i) {
        int i2 = this._longNameOffset;
        int i3 = i2 + i;
        if (i3 < 0) {
            throw new IllegalStateException(d0.p("Internal error: long name offset overflow; start=", i2, ", qlen=", i));
        }
        int[] iArr2 = this._hashArea;
        if (i3 > iArr2.length) {
            int length = i3 - iArr2.length;
            int iMin = Math.min(4096, this._hashSize);
            this._hashArea = Arrays.copyOf(this._hashArea, Math.max(length, iMin) + this._hashArea.length);
        }
        System.arraycopy(iArr, 0, this._hashArea, i2, i);
        this._longNameOffset = i3;
        return i2;
    }

    private final int _calcOffset(int i) {
        return (i & (this._hashSize - 1)) << 2;
    }

    public static int _calcTertiaryShift(int i) {
        int i2 = i >> 2;
        if (i2 < 64) {
            return 4;
        }
        if (i2 <= 256) {
            return 5;
        }
        return i2 <= 1024 ? 6 : 7;
    }

    private boolean _checkNeedForRehash() {
        if (this._count <= (this._hashSize >> 1)) {
            return false;
        }
        int i_spilloverStart = (this._spilloverEnd - _spilloverStart()) >> 2;
        int i = this._count;
        return i_spilloverStart > ((i + 1) >> 7) || i > multiplyByFourFifths(this._hashSize);
    }

    private int _findOffsetForAdd(int i) throws StreamConstraintsException {
        int i_calcOffset = _calcOffset(i);
        int[] iArr = this._hashArea;
        if (iArr[i_calcOffset + 3] == 0) {
            return i_calcOffset;
        }
        if (_checkNeedForRehash()) {
            return _resizeAndFindOffsetForAdd(i);
        }
        int i2 = this._secondaryStart + ((i_calcOffset >> 3) << 2);
        if (iArr[i2 + 3] == 0) {
            return i2;
        }
        int i3 = this._tertiaryStart;
        int i4 = this._tertiaryShift;
        int i5 = i3 + ((i_calcOffset >> (i4 + 2)) << i4);
        int i6 = (1 << i4) + i5;
        while (i5 < i6) {
            if (iArr[i5 + 3] == 0) {
                return i5;
            }
            i5 += 4;
        }
        int i7 = this._spilloverEnd;
        int i8 = i7 + 4;
        this._spilloverEnd = i8;
        if (i8 < (this._hashSize << 3)) {
            return i7;
        }
        if (this._failOnDoS) {
            _reportTooManyCollisions();
        }
        return _resizeAndFindOffsetForAdd(i);
    }

    private String _findSecondary(int i, int i2) {
        int i3 = this._tertiaryStart;
        int i4 = this._tertiaryShift;
        int i5 = i3 + ((i >> (i4 + 2)) << i4);
        int[] iArr = this._hashArea;
        int i6 = (1 << i4) + i5;
        while (i5 < i6) {
            int i7 = iArr[i5 + 3];
            if (i2 == iArr[i5] && 1 == i7) {
                return this._names[i5 >> 2];
            }
            if (i7 == 0) {
                return null;
            }
            i5 += 4;
        }
        for (int i_spilloverStart = _spilloverStart(); i_spilloverStart < this._spilloverEnd; i_spilloverStart += 4) {
            if (i2 == iArr[i_spilloverStart] && 1 == iArr[i_spilloverStart + 3]) {
                return this._names[i_spilloverStart >> 2];
            }
        }
        return null;
    }

    private int _resizeAndFindOffsetForAdd(int i) throws StreamConstraintsException {
        rehash();
        int i_calcOffset = _calcOffset(i);
        int[] iArr = this._hashArea;
        if (iArr[i_calcOffset + 3] == 0) {
            return i_calcOffset;
        }
        int i2 = this._secondaryStart + ((i_calcOffset >> 3) << 2);
        if (iArr[i2 + 3] == 0) {
            return i2;
        }
        int i3 = this._tertiaryStart;
        int i4 = this._tertiaryShift;
        int i5 = i3 + ((i_calcOffset >> (i4 + 2)) << i4);
        int i6 = (1 << i4) + i5;
        while (i5 < i6) {
            if (iArr[i5 + 3] == 0) {
                return i5;
            }
            i5 += 4;
        }
        int i7 = this._spilloverEnd;
        this._spilloverEnd = i7 + 4;
        return i7;
    }

    private final int _spilloverStart() {
        int i = this._hashSize;
        return (i << 3) - i;
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0023 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:14:0x0024  */
    /* JADX WARN: Removed duplicated region for block: B:18:0x0031 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0032  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x003f A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0040  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x004d A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:29:0x004e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private boolean _verifyLongName(int[] r8, int r9, int r10) {
        /*
            r7 = this;
            int[] r0 = r7._hashArea
            r1 = 1
            r2 = 0
            switch(r9) {
                case 4: goto L42;
                case 5: goto L34;
                case 6: goto L26;
                case 7: goto L18;
                case 8: goto Lc;
                default: goto L7;
            }
        L7:
            boolean r8 = r7._verifyLongName2(r8, r9, r10)
            return r8
        Lc:
            r9 = r8[r2]
            int r3 = r10 + 1
            r10 = r0[r10]
            if (r9 == r10) goto L15
            return r2
        L15:
            r9 = r1
            r10 = r3
            goto L19
        L18:
            r9 = r2
        L19:
            int r3 = r9 + 1
            r9 = r8[r9]
            int r4 = r10 + 1
            r10 = r0[r10]
            if (r9 == r10) goto L24
            return r2
        L24:
            r10 = r4
            goto L27
        L26:
            r3 = r2
        L27:
            int r9 = r3 + 1
            r3 = r8[r3]
            int r4 = r10 + 1
            r10 = r0[r10]
            if (r3 == r10) goto L32
            return r2
        L32:
            r10 = r4
            goto L35
        L34:
            r9 = r2
        L35:
            int r3 = r9 + 1
            r9 = r8[r9]
            int r4 = r10 + 1
            r10 = r0[r10]
            if (r9 == r10) goto L40
            return r2
        L40:
            r10 = r4
            goto L43
        L42:
            r3 = r2
        L43:
            int r9 = r3 + 1
            r4 = r8[r3]
            int r5 = r10 + 1
            r6 = r0[r10]
            if (r4 == r6) goto L4e
            return r2
        L4e:
            int r4 = r3 + 2
            r9 = r8[r9]
            int r6 = r10 + 2
            r5 = r0[r5]
            if (r9 == r5) goto L59
            return r2
        L59:
            int r3 = r3 + 3
            r9 = r8[r4]
            int r10 = r10 + 3
            r4 = r0[r6]
            if (r9 == r4) goto L64
            return r2
        L64:
            r8 = r8[r3]
            r9 = r0[r10]
            if (r8 == r9) goto L6b
            return r2
        L6b:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.fasterxml.jackson.core.sym.ByteQuadsCanonicalizer._verifyLongName(int[], int, int):boolean");
    }

    private boolean _verifyLongName2(int[] iArr, int i, int i2) {
        int i3 = 0;
        while (true) {
            int i4 = i3 + 1;
            int i5 = i2 + 1;
            if (iArr[i3] != this._hashArea[i2]) {
                return false;
            }
            if (i4 >= i) {
                return true;
            }
            i3 = i4;
            i2 = i5;
        }
    }

    private void _verifySharing() {
        if (this._hashShared) {
            if (this._parent == null) {
                if (this._count != 0) {
                    throw new IllegalStateException("Internal error: Cannot add names to Placeholder symbol table");
                }
                throw new IllegalStateException("Internal error: Cannot add names to Root symbol table");
            }
            int[] iArr = this._hashArea;
            this._hashArea = Arrays.copyOf(iArr, iArr.length);
            String[] strArr = this._names;
            this._names = (String[]) Arrays.copyOf(strArr, strArr.length);
            this._hashShared = false;
        }
    }

    public static ByteQuadsCanonicalizer createRoot() {
        long jCurrentTimeMillis = System.currentTimeMillis();
        return createRoot((((int) jCurrentTimeMillis) + ((int) (jCurrentTimeMillis >>> 32))) | 1);
    }

    private void mergeChild(TableInfo tableInfo) {
        int i = tableInfo.count;
        TableInfo tableInfo2 = this._tableInfo.get();
        if (i == tableInfo2.count) {
            return;
        }
        if (i > 6000) {
            tableInfo = TableInfo.createInitial(64);
        }
        AtomicReference<TableInfo> atomicReference = this._tableInfo;
        while (!atomicReference.compareAndSet(tableInfo2, tableInfo) && atomicReference.get() == tableInfo2) {
        }
    }

    public static int multiplyByFourFifths(int i) {
        return (int) ((i * 3435973837L) >>> 32);
    }

    private void nukeSymbols(boolean z) {
        this._count = 0;
        this._spilloverEnd = _spilloverStart();
        this._longNameOffset = this._hashSize << 3;
        if (z) {
            Arrays.fill(this._hashArea, 0);
            Arrays.fill(this._names, (Object) null);
        }
    }

    private void rehash() throws StreamConstraintsException {
        this._hashShared = false;
        int[] iArr = this._hashArea;
        String[] strArr = this._names;
        int i = this._hashSize;
        int i2 = this._count;
        int i3 = i + i;
        int i4 = this._spilloverEnd;
        if (i3 > 65536) {
            nukeSymbols(true);
            return;
        }
        this._hashArea = new int[iArr.length + (i << 3)];
        this._hashSize = i3;
        int i5 = i3 << 2;
        this._secondaryStart = i5;
        this._tertiaryStart = i5 + (i5 >> 1);
        this._tertiaryShift = _calcTertiaryShift(i3);
        this._names = new String[strArr.length << 1];
        nukeSymbols(false);
        int[] iArr2 = new int[16];
        int i6 = 0;
        for (int i7 = 0; i7 < i4; i7 += 4) {
            int i8 = iArr[i7 + 3];
            if (i8 != 0) {
                i6++;
                String str = strArr[i7 >> 2];
                if (i8 == 1) {
                    iArr2[0] = iArr[i7];
                    addName(str, iArr2, 1);
                } else if (i8 == 2) {
                    iArr2[0] = iArr[i7];
                    iArr2[1] = iArr[i7 + 1];
                    addName(str, iArr2, 2);
                } else if (i8 != 3) {
                    if (i8 > iArr2.length) {
                        iArr2 = new int[i8];
                    }
                    System.arraycopy(iArr, iArr[i7 + 1], iArr2, 0, i8);
                    addName(str, iArr2, i8);
                } else {
                    iArr2[0] = iArr[i7];
                    iArr2[1] = iArr[i7 + 1];
                    iArr2[2] = iArr[i7 + 2];
                    addName(str, iArr2, 3);
                }
            }
        }
        if (i6 != i2) {
            throw new IllegalStateException(d0.p("Internal error: Failed rehash(), old count=", i2, ", copyCount=", i6));
        }
    }

    public void _reportTooManyCollisions() throws StreamConstraintsException {
        if (this._hashSize <= 1024) {
            return;
        }
        StringBuilder sb = new StringBuilder("Spill-over slots in symbol table with ");
        sb.append(this._count);
        sb.append(" entries, hash area of ");
        sb.append(this._hashSize);
        sb.append(" slots is now full (all ");
        throw new StreamConstraintsException(a.r(sb, this._hashSize >> 3, " slots -- suspect a DoS attack based on hash collisions. You can disable the check via `JsonFactory.Feature.FAIL_ON_SYMBOL_HASH_OVERFLOW`"));
    }

    public String addName(String str, int[] iArr, int i) throws StreamConstraintsException {
        int i_findOffsetForAdd;
        _verifySharing();
        InternCache internCache = this._interner;
        if (internCache != null) {
            str = internCache.intern(str);
        }
        if (i == 1) {
            i_findOffsetForAdd = _findOffsetForAdd(calcHash(iArr[0]));
            int[] iArr2 = this._hashArea;
            iArr2[i_findOffsetForAdd] = iArr[0];
            iArr2[i_findOffsetForAdd + 3] = 1;
        } else if (i == 2) {
            i_findOffsetForAdd = _findOffsetForAdd(calcHash(iArr[0], iArr[1]));
            int[] iArr3 = this._hashArea;
            iArr3[i_findOffsetForAdd] = iArr[0];
            iArr3[i_findOffsetForAdd + 1] = iArr[1];
            iArr3[i_findOffsetForAdd + 3] = 2;
        } else if (i != 3) {
            int iCalcHash = calcHash(iArr, i);
            i_findOffsetForAdd = _findOffsetForAdd(iCalcHash);
            this._hashArea[i_findOffsetForAdd] = iCalcHash;
            int i_appendLongName = _appendLongName(iArr, i);
            int[] iArr4 = this._hashArea;
            iArr4[i_findOffsetForAdd + 1] = i_appendLongName;
            iArr4[i_findOffsetForAdd + 3] = i;
        } else {
            int i_findOffsetForAdd2 = _findOffsetForAdd(calcHash(iArr[0], iArr[1], iArr[2]));
            int[] iArr5 = this._hashArea;
            iArr5[i_findOffsetForAdd2] = iArr[0];
            iArr5[i_findOffsetForAdd2 + 1] = iArr[1];
            iArr5[i_findOffsetForAdd2 + 2] = iArr[2];
            iArr5[i_findOffsetForAdd2 + 3] = 3;
            i_findOffsetForAdd = i_findOffsetForAdd2;
        }
        this._names[i_findOffsetForAdd >> 2] = str;
        this._count++;
        return str;
    }

    public int calcHash(int i) {
        int i2 = i ^ this._seed;
        int i3 = i2 + (i2 >>> 16);
        int i4 = i3 ^ (i3 << 3);
        return i4 + (i4 >>> 12);
    }

    public String findName(int i) {
        int i_calcOffset = _calcOffset(calcHash(i));
        int[] iArr = this._hashArea;
        int i2 = iArr[i_calcOffset + 3];
        if (i2 == 1) {
            if (iArr[i_calcOffset] == i) {
                return this._names[i_calcOffset >> 2];
            }
        } else if (i2 == 0) {
            return null;
        }
        int i3 = this._secondaryStart + ((i_calcOffset >> 3) << 2);
        int i4 = iArr[i3 + 3];
        if (i4 == 1) {
            if (iArr[i3] == i) {
                return this._names[i3 >> 2];
            }
        } else if (i4 == 0) {
            return null;
        }
        return _findSecondary(i_calcOffset, i);
    }

    public ByteQuadsCanonicalizer makeChild(int i) {
        return new ByteQuadsCanonicalizer(this, this._seed, this._tableInfo.get(), JsonFactory.Feature.INTERN_FIELD_NAMES.enabledIn(i), JsonFactory.Feature.FAIL_ON_SYMBOL_HASH_OVERFLOW.enabledIn(i));
    }

    public boolean maybeDirty() {
        return !this._hashShared;
    }

    public int primaryCount() {
        int i = this._secondaryStart;
        int i2 = 0;
        for (int i3 = 3; i3 < i; i3 += 4) {
            if (this._hashArea[i3] != 0) {
                i2++;
            }
        }
        return i2;
    }

    public void release() {
        if (this._parent == null || !maybeDirty()) {
            return;
        }
        this._parent.mergeChild(new TableInfo(this));
        this._hashShared = true;
    }

    public int secondaryCount() {
        int i = this._tertiaryStart;
        int i2 = 0;
        for (int i3 = this._secondaryStart + 3; i3 < i; i3 += 4) {
            if (this._hashArea[i3] != 0) {
                i2++;
            }
        }
        return i2;
    }

    public int spilloverCount() {
        return (this._spilloverEnd - _spilloverStart()) >> 2;
    }

    public int tertiaryCount() {
        int i = this._tertiaryStart + 3;
        int i2 = this._hashSize + i;
        int i3 = 0;
        while (i < i2) {
            if (this._hashArea[i] != 0) {
                i3++;
            }
            i += 4;
        }
        return i3;
    }

    public String toString() {
        int iPrimaryCount = primaryCount();
        int iSecondaryCount = secondaryCount();
        int iTertiaryCount = tertiaryCount();
        int iSpilloverCount = spilloverCount();
        return String.format("[%s: size=%d, hashSize=%d, %d/%d/%d/%d pri/sec/ter/spill (=%s), total:%d]", ByteQuadsCanonicalizer.class.getName(), Integer.valueOf(this._count), Integer.valueOf(this._hashSize), Integer.valueOf(iPrimaryCount), Integer.valueOf(iSecondaryCount), Integer.valueOf(iTertiaryCount), Integer.valueOf(iSpilloverCount), Integer.valueOf(iPrimaryCount + iSecondaryCount + iTertiaryCount + iSpilloverCount), Integer.valueOf(totalCount()));
    }

    public int totalCount() {
        int i = this._hashSize << 3;
        int i2 = 0;
        for (int i3 = 3; i3 < i; i3 += 4) {
            if (this._hashArea[i3] != 0) {
                i2++;
            }
        }
        return i2;
    }

    public int calcHash(int i, int i2) {
        int i3 = i + (i >>> 15);
        int i4 = this._seed ^ ((i2 * 33) + (i3 ^ (i3 >>> 9)));
        int i5 = i4 + (i4 >>> 16);
        int i6 = i5 ^ (i5 >>> 4);
        return i6 + (i6 << 3);
    }

    public static ByteQuadsCanonicalizer createRoot(int i) {
        return new ByteQuadsCanonicalizer(64, i);
    }

    public int calcHash(int i, int i2, int i3) {
        int i4 = i ^ this._seed;
        int i5 = (((i4 + (i4 >>> 9)) * 31) + i2) * 33;
        int i6 = (i5 + (i5 >>> 15)) ^ i3;
        int i7 = i6 + (i6 >>> 4);
        int i8 = i7 + (i7 >>> 15);
        return i8 ^ (i8 << 9);
    }

    public int calcHash(int[] iArr, int i) {
        if (i >= 4) {
            int i2 = iArr[0] ^ this._seed;
            int i3 = i2 + (i2 >>> 9) + iArr[1];
            int i4 = ((i3 + (i3 >>> 15)) * 33) ^ iArr[2];
            int i5 = i4 + (i4 >>> 4);
            for (int i6 = 3; i6 < i; i6++) {
                int i7 = iArr[i6];
                i5 += i7 ^ (i7 >> 21);
            }
            int i8 = i5 * 65599;
            int i9 = i8 + (i8 >>> 19);
            return (i9 << 5) ^ i9;
        }
        throw new IllegalArgumentException("qlen is too short, needs to be at least 4");
    }

    public static final class TableInfo {
        public final int count;
        public final int longNameOffset;
        public final int[] mainHash;
        public final String[] names;
        public final int size;
        public final int spilloverEnd;
        public final int tertiaryShift;

        public TableInfo(int i, int i2, int i3, int[] iArr, String[] strArr, int i4, int i5) {
            this.size = i;
            this.count = i2;
            this.tertiaryShift = i3;
            this.mainHash = iArr;
            this.names = strArr;
            this.spilloverEnd = i4;
            this.longNameOffset = i5;
        }

        public static TableInfo createInitial(int i) {
            int i2 = i << 3;
            return new TableInfo(i, 0, ByteQuadsCanonicalizer._calcTertiaryShift(i), new int[i2], new String[i << 1], i2 - i, i2);
        }

        public TableInfo(ByteQuadsCanonicalizer byteQuadsCanonicalizer) {
            this.size = byteQuadsCanonicalizer._hashSize;
            this.count = byteQuadsCanonicalizer._count;
            this.tertiaryShift = byteQuadsCanonicalizer._tertiaryShift;
            this.mainHash = byteQuadsCanonicalizer._hashArea;
            this.names = byteQuadsCanonicalizer._names;
            this.spilloverEnd = byteQuadsCanonicalizer._spilloverEnd;
            this.longNameOffset = byteQuadsCanonicalizer._longNameOffset;
        }
    }

    private ByteQuadsCanonicalizer(ByteQuadsCanonicalizer byteQuadsCanonicalizer, int i, TableInfo tableInfo, boolean z, boolean z2) {
        this._parent = byteQuadsCanonicalizer;
        this._seed = i;
        this._interner = z ? InternCache.instance : null;
        this._failOnDoS = z2;
        this._tableInfo = null;
        this._count = tableInfo.count;
        int i2 = tableInfo.size;
        this._hashSize = i2;
        int i3 = i2 << 2;
        this._secondaryStart = i3;
        this._tertiaryStart = i3 + (i3 >> 1);
        this._tertiaryShift = tableInfo.tertiaryShift;
        this._hashArea = tableInfo.mainHash;
        this._names = tableInfo.names;
        this._spilloverEnd = tableInfo.spilloverEnd;
        this._longNameOffset = tableInfo.longNameOffset;
        this._hashShared = true;
    }

    private String _findSecondary(int i, int i2, int i3) {
        int i4 = this._tertiaryStart;
        int i5 = this._tertiaryShift;
        int i6 = i4 + ((i >> (i5 + 2)) << i5);
        int[] iArr = this._hashArea;
        int i7 = (1 << i5) + i6;
        while (i6 < i7) {
            int i8 = iArr[i6 + 3];
            if (i2 == iArr[i6] && i3 == iArr[i6 + 1] && 2 == i8) {
                return this._names[i6 >> 2];
            }
            if (i8 == 0) {
                return null;
            }
            i6 += 4;
        }
        for (int i_spilloverStart = _spilloverStart(); i_spilloverStart < this._spilloverEnd; i_spilloverStart += 4) {
            if (i2 == iArr[i_spilloverStart] && i3 == iArr[i_spilloverStart + 1] && 2 == iArr[i_spilloverStart + 3]) {
                return this._names[i_spilloverStart >> 2];
            }
        }
        return null;
    }

    public String findName(int i, int i2) {
        int i_calcOffset = _calcOffset(calcHash(i, i2));
        int[] iArr = this._hashArea;
        int i3 = iArr[i_calcOffset + 3];
        if (i3 == 2) {
            if (i == iArr[i_calcOffset] && i2 == iArr[i_calcOffset + 1]) {
                return this._names[i_calcOffset >> 2];
            }
        } else if (i3 == 0) {
            return null;
        }
        int i4 = this._secondaryStart + ((i_calcOffset >> 3) << 2);
        int i5 = iArr[i4 + 3];
        if (i5 == 2) {
            if (i == iArr[i4] && i2 == iArr[i4 + 1]) {
                return this._names[i4 >> 2];
            }
        } else if (i5 == 0) {
            return null;
        }
        return _findSecondary(i_calcOffset, i, i2);
    }

    private String _findSecondary(int i, int i2, int i3, int i4) {
        int i5 = this._tertiaryStart;
        int i6 = this._tertiaryShift;
        int i7 = i5 + ((i >> (i6 + 2)) << i6);
        int[] iArr = this._hashArea;
        int i8 = (1 << i6) + i7;
        while (i7 < i8) {
            int i9 = iArr[i7 + 3];
            if (i2 == iArr[i7] && i3 == iArr[i7 + 1] && i4 == iArr[i7 + 2] && 3 == i9) {
                return this._names[i7 >> 2];
            }
            if (i9 == 0) {
                return null;
            }
            i7 += 4;
        }
        for (int i_spilloverStart = _spilloverStart(); i_spilloverStart < this._spilloverEnd; i_spilloverStart += 4) {
            if (i2 == iArr[i_spilloverStart] && i3 == iArr[i_spilloverStart + 1] && i4 == iArr[i_spilloverStart + 2] && 3 == iArr[i_spilloverStart + 3]) {
                return this._names[i_spilloverStart >> 2];
            }
        }
        return null;
    }

    public String findName(int i, int i2, int i3) {
        int i_calcOffset = _calcOffset(calcHash(i, i2, i3));
        int[] iArr = this._hashArea;
        int i4 = iArr[i_calcOffset + 3];
        if (i4 == 3) {
            if (i == iArr[i_calcOffset] && iArr[i_calcOffset + 1] == i2 && iArr[i_calcOffset + 2] == i3) {
                return this._names[i_calcOffset >> 2];
            }
        } else if (i4 == 0) {
            return null;
        }
        int i5 = this._secondaryStart + ((i_calcOffset >> 3) << 2);
        int i6 = iArr[i5 + 3];
        if (i6 == 3) {
            if (i == iArr[i5] && iArr[i5 + 1] == i2 && iArr[i5 + 2] == i3) {
                return this._names[i5 >> 2];
            }
        } else if (i6 == 0) {
            return null;
        }
        return _findSecondary(i_calcOffset, i, i2, i3);
    }

    private String _findSecondary(int i, int i2, int[] iArr, int i3) {
        int i4 = this._tertiaryStart;
        int i5 = this._tertiaryShift;
        int i6 = i4 + ((i >> (i5 + 2)) << i5);
        int[] iArr2 = this._hashArea;
        int i7 = (1 << i5) + i6;
        while (i6 < i7) {
            int i8 = iArr2[i6 + 3];
            if (i2 == iArr2[i6] && i3 == i8 && _verifyLongName(iArr, i3, iArr2[i6 + 1])) {
                return this._names[i6 >> 2];
            }
            if (i8 == 0) {
                return null;
            }
            i6 += 4;
        }
        for (int i_spilloverStart = _spilloverStart(); i_spilloverStart < this._spilloverEnd; i_spilloverStart += 4) {
            if (i2 == iArr2[i_spilloverStart] && i3 == iArr2[i_spilloverStart + 3] && _verifyLongName(iArr, i3, iArr2[i_spilloverStart + 1])) {
                return this._names[i_spilloverStart >> 2];
            }
        }
        return null;
    }

    public String findName(int[] iArr, int i) {
        if (i < 4) {
            if (i == 1) {
                return findName(iArr[0]);
            }
            if (i == 2) {
                return findName(iArr[0], iArr[1]);
            }
            if (i != 3) {
                return "";
            }
            return findName(iArr[0], iArr[1], iArr[2]);
        }
        int iCalcHash = calcHash(iArr, i);
        int i_calcOffset = _calcOffset(iCalcHash);
        int[] iArr2 = this._hashArea;
        int i2 = iArr2[i_calcOffset + 3];
        if (iCalcHash == iArr2[i_calcOffset] && i2 == i && _verifyLongName(iArr, i, iArr2[i_calcOffset + 1])) {
            return this._names[i_calcOffset >> 2];
        }
        if (i2 == 0) {
            return null;
        }
        int i3 = this._secondaryStart + ((i_calcOffset >> 3) << 2);
        int i4 = iArr2[i3 + 3];
        if (iCalcHash == iArr2[i3] && i4 == i && _verifyLongName(iArr, i, iArr2[i3 + 1])) {
            return this._names[i3 >> 2];
        }
        return _findSecondary(i_calcOffset, iCalcHash, iArr, i);
    }
}
