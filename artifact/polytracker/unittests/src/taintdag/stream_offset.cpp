#include <catch2/catch.hpp>

#include "taintdag/stream_offset.h"

#include "utils.h"

namespace taintdag {

TEST_CASE("StreamOffset", "StreamOffset") {

  StreamOffset<4> ofs;
  REQUIRE(ofs.increase(0, 0) == 0);
  REQUIRE(ofs.increase(0, 0) == 0);

  SECTION("Reading 3 bytes twice") {
    REQUIRE(ofs.increase(0, 3) == 0);
    REQUIRE(ofs.increase(0, 3) == 3);
  }

  SECTION("Reads doesn't interfer") {
    ofs.increase(0, 99);
    ofs.increase(1, 2);

    REQUIRE(ofs.increase(0, 1) == 99);
    REQUIRE(ofs.increase(1, 1) == 2);
  }

  SECTION("SourceIndex out of bounds aborts") {
    test::ErrorExitReplace errthrow;
    REQUIRE_THROWS_AS(ofs.increase(4, 1), test::ErrorExit);
  }
}

}