# runs inside the bf2 server. dumps player state to a file, applies actions
# bf2am writes. add `import bf2am_shim` to mods/bf2/python/game/__init__.py
# NOTE: written from memory of the bf2 python api, not tested on a real server yet
import bf2
import host

STATE = "state.txt"
ACTIONS = "actions.txt"
AIR = (1, 3)  # VEHICLE_TYPE_AVIATOR, VEHICLE_TYPE_HELICOPTER


def _air(p):
    try:
        v = bf2.objectManager.getRootParent(p.getVehicle())
        return int(v.getTemplateProperty("vehicleType")) in AIR
    except Exception:
        return False


def _dump():
    out = []
    for p in bf2.playerManager.getPlayers():
        try:
            x, y, z = p.getVehicle().getPosition()
            name = p.getName().replace("\n", " ")
            out.append("P %d %d %d %d %d %d %s" % (
                p.index, p.getTeam(), 1 if _air(p) else 0,
                int(x), int(z), p.score.score, name))
        except Exception:
            pass
    f = open(STATE, "w")
    f.write("\n".join(out) + "\n")
    f.close()


def _apply():
    try:
        f = open(ACTIONS, "r")
        lines = f.readlines()
        f.close()
        open(ACTIONS, "w").close()
    except IOError:
        return
    for l in lines:
        parts = l.split()
        if len(parts) != 2:
            continue
        try:
            p = bf2.playerManager.getPlayerByIndex(int(parts[1]))
            if parts[0] == "swap":
                p.setTeam(3 - p.getTeam())
            elif parts[0] == "kill":
                p.getVehicle().setDamage(1)
        except Exception:
            pass


def _tick(data):
    _dump()
    _apply()


_t = bf2.Timer(_tick, 2, 1)
_t.setRecurring(2)
