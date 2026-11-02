#include "cet2_function.h"

namespace cet2
{
namespace
{

Result RunFunctionChain(const void* function,
                        std::initializer_list<std::uint64_t> args, int frames)
{
    if (!function || args.size() > 5)
    {
        return {};
    }
    std::uint64_t buffer[5] = {};
    std::size_t i = 0;
    for (const auto value : args)
    {
        if (i < 5)
        {
            buffer[i++] = value;
        }
    }
    if (frames == 2)
    {
        return detail::RunChain2(const_cast<void*>(function), 0, buffer,
                                 args.size());
    }
    return detail::RunChain3(const_cast<void*>(function), 0, buffer,
                             args.size());
}

} // namespace

Result CallFunction(const void* function,
                    std::initializer_list<std::uint64_t> args)
{
    return RunFunctionChain(function, args, 2);
}

Result CallFunction3(const void* function,
                     std::initializer_list<std::uint64_t> args)
{
    return RunFunctionChain(function, args, 3);
}

} // namespace cet2
