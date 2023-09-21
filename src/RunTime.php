<?php

namespace JustSecurityCheck\Console;

use DateTime;
use Exception;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class RunTime extends Command
{
    private $total = 0;

    protected function configure()
    {
        $this->setName('run:time')
            ->setAliases(['time', 't'])
            ->setDescription('Check for security advisories for the packages in your composer.json')
            ->addOption('dev', 'd', InputOption::VALUE_NONE, 'If require-dev should be checked as well')
            ->addOption('date', 'D', InputOption::VALUE_REQUIRED, 'Max package date.')
            ->addOption('allow',  'a', InputOption::VALUE_REQUIRED, 'Exclude some vulnerabilities,')
            ->addOption('exclude', 'e', InputOption::VALUE_REQUIRED, 'Exclude some vulnerabilities,');
    }

    /**
     * @throws Exception
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        if ($input->getOption('date')) {
            $maxDate = $input->getOption('date');
        } else {
            $maxDate = '2022-02-24';
        }
        $maxDate = new DateTime($maxDate);

        $allowVendor = [];
        $allowPackages = [];
        if ($input->getOption('allow')) {
            $this->getAE($input->getOption('allow'), $allowVendor, $allowPackages);
        }

        $excludeVendor = [];
        $excludePackages = [];
        if ($input->getOption('exclude')) {
            $this->getAE($input->getOption('exclude'), $excludeVendor, $excludePackages);
        }

        $dir = getcwd() . '/';

        if (!file_exists($dir . 'composer.lock')) {
            $output->writeln('<fg=red>No composer.lock file found !</>');

            return 1;
        }

        $composerLock = file_get_contents($dir . 'composer.lock');

        $json = json_decode($composerLock, true);

        if (!array_key_exists('packages', $json)) {
            $output->writeln('<fg=red>There is no "require" !</>');
            return 1;
        }

        if ($input->getOption('dev')) {
            if (!array_key_exists('packages-dev', $json)) {
                $output->writeln('<fg=red>There is no "require-dev" !</>');
                return 1;
            }
        }

        $this->parsePackages(
            $output,
            'packages:',
            $json['packages'],
            $maxDate,
            $allowVendor,
            $allowPackages,
            $excludeVendor,
            $excludePackages
        );

        if ($input->getOption('dev')) {
            $this->parsePackages(
                $output,
                'packages-dev:',
                $json['packages-dev'],
                $maxDate,
                $allowVendor,
                $allowPackages,
                $excludeVendor,
                $excludePackages
            );
        }

        $resFormat = $this->total . ' packages';
        $res = 0;
        if ($this->total > 0) {
            $res = 1;
            $resFormat = '<fg=red>' . $this->total . ' packages</>';
        }
        $output->writeln(PHP_EOL . $resFormat . ' released after date: ' . $maxDate->format('Y-m-d'));
        return $res;
    }

    /**
     * @param string $str
     * @param array $vendor
     * @param array $packages
     * @return void
     */
    private function getAE($str, &$vendor, &$packages)
    {
        $arr = explode(',', $str);
        foreach ($arr as $item) {
            $vanPack = explode('/', $item);
            if (!isset($vanPack[1])) {
                $vendor[trim($vanPack[0])] = 1;
            } elseif (isset($vanPack[1]) && (trim($vanPack[1]) === '*' ||  trim($vanPack[1]) === '')) {
                $vendor[trim($vanPack[0])] = 1;
            } else {
                $packages[trim($item)] = 1;
            }
        }
    }

    /**
     * @param OutputInterface $output
     * @param string $comment
     * @param array $packages
     * @param DateTime $maxDate
     * @param array $allowVendor
     * @param array $allowPackages
     * @param array $excludeVendor
     * @param array $excludePackages
     * @return void
     * @throws Exception
     */
    private function parsePackages(
        $output,
        $comment,
        &$packages,
        &$maxDate,
        &$allowVendor,
        &$allowPackages,
        &$excludeVendor,
        &$excludePackages
    ) {
        $output->writeln(PHP_EOL . $comment);
        $count = 0;
        foreach ($packages as $package) {
            if (isset($excludePackages[$package['name']]) ||
                isset($excludeVendor[explode('/', $package['name'])[0]])) {
                continue;
            }

            $pTime = new DateTime($package['time']);
            if ($pTime > $maxDate) {
                $color = 'red';
                $allow = '';
                if (isset($allowPackages[$package['name']]) ||
                    isset($allowVendor[explode('/', $package['name'])[0]])) {
                    $color = 'magenta';
                    $allow = '<fg=magenta> allowed</>';
                } else {
                    ++$this->total;
                }

                $link = ' https://packagist.org/packages/' . $package['name'] . '#' . $package['version'];

                $output
                    ->writeln(
                        ++$count . '. ' .
                        '<fg=green>' . $package['name'] . '</> <fg=' . $color . '>(' . $package['version'] .
                        ') '.$pTime->format('Y-m-d').'</>' . $allow . $link
                    );
            }
        }
    }
}
